"""vltlib — storage, crypto and policy core for the vlt credential vault.

One record per file, AES-256-GCM, per-record subkey derived from a master key that
lives in gnome-keyring (never on disk). Values never pass through stdout unless a
human asks; agents get structure only.
"""

import fcntl
import glob as _glob
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --------------------------------------------------------------------------- paths

HOME = os.path.expanduser("~")
ROOT = os.environ.get("VLT_HOME", os.path.join(HOME, ".local/share/vlt"))
STORE = os.path.join(ROOT, "store")
TEMPLATES = os.path.join(ROOT, "templates")
INDEX = os.path.join(ROOT, "index.json")
AUDIT = os.path.join(ROOT, "audit.log")
POLICY = os.path.join(ROOT, "policy.json")
GUARD = os.path.join(ROOT, "guard.mode")
BACKUP = os.path.join(ROOT, "backup")

# The default vault keeps the original label so existing installs keep opening.
# Any other VLT_HOME gets its own entry, so two vaults on one machine do not
# silently share a master key.
_DEFAULT_ROOT = os.path.normpath(os.path.join(HOME, ".local/share/vlt"))


def _keyring_id(root):
    root = os.path.normpath(root)
    if root == _DEFAULT_ROOT:
        return "vlt-master-identity", "master-identity"
    import hashlib
    tag = hashlib.sha256(root.encode()).hexdigest()[:12]
    return "vlt-master-identity (%s)" % root, "master-identity:%s" % tag


KEYRING_LABEL, _KEYRING_PURPOSE = _keyring_id(ROOT)
KEYRING_ATTRS = {"application": "vlt", "purpose": _KEYRING_PURPOSE}
FALLBACK_KEY = os.path.join(ROOT, ".master.key")  # only if keyring unavailable

MAGIC = b"VLT1"

# --------------------------------------------------------------- generalized schema

# Fixed field vocabulary. Everything else goes in `extra`.
FIELDS = [
    "username", "password", "token", "key", "secret",
    "host", "port", "url", "path", "region", "account_id",
]
# Masking is fail-closed: everything is hidden EXCEPT these, which are
# addressing and identity rather than credentials. A field the schema has never
# seen is therefore masked, not printed.
#
# `url` is deliberately NOT here: admin panel URLs, webhook URLs and connection
# strings routinely carry a secret path or an embedded token.
DEFAULT_PUBLIC = {"username", "host", "port", "region", "account_id", "path"}

# Canonical fields that are always credentials, whatever else is configured.
DEFAULT_HIDDEN = {"password", "token", "key", "secret", "url"}
SECRET_FIELDS = DEFAULT_HIDDEN
PUBLIC_FIELDS = DEFAULT_PUBLIC

TYPES = [
    "login", "token", "apikey", "oauth", "ssh",
    "database", "cert", "vpn", "smtp", "service",
]

# --------------------------------------------------------- multi-line values
# Not every credential is a line of text. An OpenSSH private key, a PEM
# certificate and a service-account blob all contain newlines, and a reader
# that stops at the first one stores an armour header and calls it a key.
# These fields are offered a multi-line editor by default; any other field is
# promoted to one the moment its value turns out to span lines.
MULTILINE_FIELDS = {"key", "cert", "certificate", "private_key",
                    "ca", "ca_cert", "pubkey", "public_key"}

# `-----BEGIN OPENSSH PRIVATE KEY-----`, `-----BEGIN CERTIFICATE-----`, and so
# on. The armour is what makes auto-detection possible: a value that opens with
# one of these is known to continue until the matching END.
PEM_BEGIN_RE = re.compile(r"^-{5}BEGIN [A-Z0-9][A-Z0-9 ]*-{5}\s*$")
PEM_END_RE = re.compile(r"^-{5}END [A-Z0-9][A-Z0-9 ]*-{5}\s*$")


def is_armoured(value):
    """Does this value open with a PEM/OpenSSH armour line?"""
    if not value:
        return False
    first = value.replace("\r\n", "\n").split("\n", 1)[0]
    return bool(PEM_BEGIN_RE.match(first))


def normalise_multiline(value):
    """CRLF to LF, and a terminating newline on anything armoured.

    OpenSSH and every PEM parser require the final `-----END ...-----` to be
    followed by a newline. A key stored without one is rejected as "invalid
    format", which reads like the wrong key rather than a missing byte — so the
    byte is added here, once, rather than at each of the places a key is
    written out. Values that are not armoured are returned untouched: a
    password may legitimately contain anything at all.
    """
    if not isinstance(value, str) or not is_armoured(value):
        return value
    v = value.replace("\r\n", "\n").replace("\r", "\n")
    return v if v.endswith("\n") else v + "\n"


NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*){0,3}$")


def blank_record(name, rtype="token"):
    return {
        "name": name,
        "type": rtype,
        "provider": name.split("/")[0],
        "account": "",
        "fields": {f: None for f in FIELDS},
        "extra": {},
        "env_map": {},
        "created": _now(),
        "rotated": None,
        "expires": None,
        "tags": [],
        "notes": "",
        # Which fields `peek` masks. None means "use DEFAULT_HIDDEN".
        "hidden": None,
    }


def normalize(rec):
    """Force any record onto the generalized structure."""
    out = blank_record(rec.get("name", ""), rec.get("type") or "token")
    for k in ("name", "type", "provider", "account", "created", "rotated",
              "expires", "notes"):
        if rec.get(k) is not None:
            out[k] = rec[k]
    out["tags"] = list(rec.get("tags") or [])
    h = rec.get("hidden", None)
    out["hidden"] = None if h is None else sorted({str(x) for x in h})
    out["extra"] = dict(rec.get("extra") or {})
    out["env_map"] = dict(rec.get("env_map") or {})
    for f, v in (rec.get("fields") or {}).items():
        if f in FIELDS:
            out["fields"][f] = v
        elif v is not None:
            out["extra"][f] = v
    if out["type"] not in TYPES:
        out["type"] = "service"
    if not out["provider"]:
        out["provider"] = out["name"].split("/")[0]
    # An armoured value gets its line endings and its terminating newline here,
    # whichever path it arrived by. See normalise_multiline.
    for f, v in list(out["fields"].items()):
        out["fields"][f] = normalise_multiline(v)
    for f, v in list(out["extra"].items()):
        out["extra"][f] = normalise_multiline(v)
    return out


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------- agent ctx

AGENT_ENV = ("CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "AI_AGENT", "ANTHROPIC_AGENT")


def is_agent():
    if os.environ.get("VLT_HUMAN") == "1":
        return False
    return any(os.environ.get(v) for v in AGENT_ENV)


def caller():
    return "agent" if is_agent() else "human"


class Denied(Exception):
    pass


# -------------------------------------------------------------------------- crypto

# Two keyring backends, chosen by platform. Both hold the same 32 raw bytes;
# only the transport encoding differs, because the macOS `security` tool speaks
# text on a pipe and the Secret Service speaks bytes over D-Bus.

SECURITY = "/usr/bin/security"          # the macOS keychain CLI


def keyring_backend():
    """'macos', 'secretservice', or None when the caller has opted out."""
    if os.environ.get("VLT_NO_KEYRING") == "1":
        return None
    forced = os.environ.get("VLT_KEYRING_BACKEND")
    if forced:
        return forced
    if sys.platform == "darwin" and os.path.exists(SECURITY):
        return "macos"
    return "secretservice"


def _use_keyring():
    """False when the caller has opted out — tests, or a deliberate file key."""
    return keyring_backend() is not None


# --------------------------------------------------------- macOS login keychain

MAC_TIMEOUT = 20        # seconds; `security` can sit waiting on a GUI prompt


def _mac(args, check=False):
    """Run `security`, and never wait on it for ever.

    Some subcommands prompt — for an unlock, or for permission — and with no
    desktop to answer, the call blocks indefinitely. A credential tool that can
    hang is a credential tool that will, in the one script nobody is watching.
    """
    import subprocess
    try:
        r = subprocess.run([SECURITY] + args, capture_output=True, text=True,
                           timeout=MAC_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "`security %s` did not return within %ds — the keychain is "
            "probably waiting for a prompt that nothing can answer."
            % (args[0], MAC_TIMEOUT))
    if check and r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or
                           "security %s failed (%d)" % (args[0], r.returncode))
    return r


def _mac_get(label=None, account=None):
    import base64
    import binascii
    r = _mac(["find-generic-password", "-s", label or KEYRING_LABEL,
              "-a", account or _KEYRING_PURPOSE, "-w"])
    if r.returncode != 0:
        return None
    text = r.stdout.strip()
    if not text:
        return None
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return text.encode()


def _mac_set(raw, label=None, account=None):
    import base64
    label = label or KEYRING_LABEL
    account = account or _KEYRING_PURPOSE
    _mac(["delete-generic-password", "-s", label, "-a", account])
    # -A means any process running as this user may read it with no per-use
    # prompt. That is the same trust model gnome-keyring gives on Linux, and it
    # is what "no passphrase on every use" costs. See docs/THREAT-MODEL.md.
    #
    # The key passes through argv for the length of this one call, so `ps` can
    # see it for that instant. It happens on `vlt init` and `vlt identity
    # import` only — never on a read — and the keychain CLI has no way to take
    # a password on stdin without a terminal to prompt at.
    _mac(["add-generic-password", "-U", "-A",
          "-s", label, "-a", account,
          "-D", "credfence master key",
          "-j", "AES-256 master key for the vlt credential vault",
          "-w", base64.b64encode(raw).decode()], check=True)


def _mac_items():
    """Every vlt-owned keychain item as (label, account). Reveals no secret.

    `dump-keychain` without -d prints attributes only, and does not prompt.
    """
    try:
        r = _mac(["dump-keychain"])
    except RuntimeError:
        # Listing is a convenience; a prompt here must not take the caller down.
        return []
    if r.returncode != 0:
        return []
    out, svce, acct = [], None, None
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("keychain:"):
            svce = acct = None
            continue
        m = re.match(r'"(svce|acct)"<blob>=(?:"(.*)"|<NULL>)$', line)
        if not m:
            continue
        if m.group(1) == "svce":
            svce = m.group(2)
        else:
            acct = m.group(2)
        if svce and acct and svce.startswith("vlt-master-identity"):
            out.append((svce, acct))
            svce = acct = None
    return out


def _mac_delete(label, account):
    _mac(["delete-generic-password", "-s", label, "-a", account], check=True)
    return True


# ------------------------------------------------------- Secret Service (Linux)

def _ss_collection(conn):
    import secretstorage
    coll = secretstorage.get_default_collection(conn)
    if coll.is_locked():
        coll.unlock()
    return coll


def _ss(fn):
    """Run fn(collection) on a connection that is always closed afterwards."""
    import secretstorage
    conn = secretstorage.dbus_init()
    try:
        return fn(_ss_collection(conn))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _ss_get():
    def go(coll):
        for item in coll.search_items(KEYRING_ATTRS):
            return item.get_secret()
        return None
    return _ss(go)


def _ss_set(raw):
    def go(coll):
        for item in coll.search_items(KEYRING_ATTRS):
            item.delete()
        coll.create_item(KEYRING_LABEL, KEYRING_ATTRS, raw, replace=True)
    return _ss(go)


def _ss_items():
    def go(coll):
        out = []
        for item in coll.get_all_items():
            attrs = item.get_attributes()
            if attrs.get("application") == "vlt":
                out.append((item.get_label(), attrs.get("purpose", "")))
        return out
    return _ss(go)


def _ss_delete(label, account):
    def go(coll):
        for item in coll.get_all_items():
            attrs = item.get_attributes()
            if (attrs.get("application") == "vlt"
                    and item.get_label() == label
                    and attrs.get("purpose", "") == account):
                item.delete()
                return True
        return False
    return _ss(go)


# --------------------------------------------------------------------- dispatch

def _keyring_get():
    b = keyring_backend()
    if b is None:
        return None
    return _mac_get() if b == "macos" else _ss_get()


def _keyring_set(raw):
    b = keyring_backend()
    if b is None:
        raise RuntimeError("keyring disabled by VLT_NO_KEYRING")
    return _mac_set(raw) if b == "macos" else _ss_set(raw)


def keyring_items():
    """(label, account) for every entry vlt owns, on whichever backend is live."""
    b = keyring_backend()
    if b is None:
        return []
    return _mac_items() if b == "macos" else _ss_items()


def keyring_delete(label, account):
    b = keyring_backend()
    if b is None:
        return False
    return _mac_delete(label, account) if b == "macos" \
        else _ss_delete(label, account)


_MASTER = None


def master_key(create=False):
    """32-byte master key. gnome-keyring first, 0400 file fallback."""
    global _MASTER
    if _MASTER is not None:
        return _MASTER
    raw = None
    try:
        raw = _keyring_get()
    except Exception:
        raw = None
    if raw is None and os.path.exists(FALLBACK_KEY):
        with open(FALLBACK_KEY, "rb") as fh:
            raw = fh.read()
    if raw is None:
        if not create:
            raise Denied(
                "vault is not initialized (no master key). Run: vlt init")
        raw = secrets.token_bytes(32)
        stored = False
        err = ""
        try:
            _keyring_set(raw)
            stored = bool(_keyring_get())
        except Exception as exc:
            err = str(exc)
            stored = False
        if not stored:
            # A plaintext key on disk is a different, weaker security model.
            # It must be chosen, never fallen into.
            if os.environ.get("VLT_ALLOW_FILE_KEY") != "1":
                which = ("the macOS login keychain"
                         if sys.platform == "darwin"
                         else "a Secret Service keyring (gnome-keyring, "
                              "kwallet, keepassxc)")
                raise Denied(
                    "no system keyring is available%s.\n"
                    "     vlt wants %s\n"
                    "     so that the master key is not a readable file.\n"
                    "     Without one, the key must live in %s at mode 0400, "
                    "which is a\n"
                    "     weaker model: anything running as you can read it "
                    "directly.\n"
                    "     If you accept that, re-run with "
                    "VLT_ALLOW_FILE_KEY=1."
                    % ((": " + err) if err else "", which, FALLBACK_KEY))
            fd = os.open(FALLBACK_KEY, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
            with os.fdopen(fd, "wb") as fh:
                fh.write(raw)
    if len(raw) != 32:
        raw = raw[:32].ljust(32, b"\0")
    _MASTER = raw
    return _MASTER


def _subkey(name):
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"vlt-record-v1", info=name.encode(),
    ).derive(master_key())


def _path(name):
    return os.path.join(STORE, name + ".vlt")


def encrypt_record(rec):
    name = rec["name"]
    data = json.dumps(rec, ensure_ascii=False).encode()
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_subkey(name)).encrypt(nonce, data, name.encode())
    return MAGIC + nonce + ct


def decrypt_record(name, blob):
    if blob[:4] != MAGIC:
        raise Denied("corrupt record: bad magic for %r" % name)
    nonce, ct = blob[4:16], blob[16:]
    data = AESGCM(_subkey(name)).decrypt(nonce, ct, name.encode())
    return json.loads(data)


# ------------------------------------------------------------------------- storage

def exists(name):
    return os.path.exists(_path(name))


def load(name):
    p = _path(name)
    if not os.path.exists(p):
        raise Denied("no such secret: %s  (try: vlt list, or vlt request %s)"
                     % (name, name))
    with open(p, "rb") as fh:
        return decrypt_record(name, fh.read())


def save(rec):
    rec = normalize(rec)
    name = rec["name"]
    if not NAME_RE.match(name):
        raise Denied(
            "bad name %r — use lowercase <provider>/<account>[/<purpose>]" % name)
    p = _path(name)
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(encrypt_record(rec))
    os.replace(tmp, p)
    reindex_one(rec)
    return p


def delete(name):
    p = _path(name)
    if os.path.exists(p):
        os.remove(p)
    idx = read_index()
    idx.pop(name, None)
    write_index(idx)


def all_names():
    out = []
    for p in _glob.glob(os.path.join(STORE, "**", "*.vlt"), recursive=True):
        out.append(os.path.relpath(p, STORE)[:-4])
    return sorted(out)


# --------------------------------------------------------------------------- index

def read_index():
    try:
        with open(INDEX) as fh:
            return json.load(fh)
    except Exception:
        return {}


def write_index(idx):
    tmp = INDEX + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(idx, fh, indent=2, sort_keys=True)
    os.replace(tmp, INDEX)


def index_entry(rec):
    """Everything about a record EXCEPT the values."""
    present = [f for f, v in rec["fields"].items() if v not in (None, "")]
    return {
        "hidden": sorted(hidden_fields(rec)),
        "name": rec["name"],
        "type": rec["type"],
        "provider": rec["provider"],
        "account": rec.get("account", ""),
        "fields": present,
        "extra_keys": sorted(rec.get("extra", {}).keys()),
        "env_map": rec.get("env_map", {}),
        "tags": rec.get("tags", []),
        "created": rec.get("created"),
        "rotated": rec.get("rotated"),
        "expires": rec.get("expires"),
        "notes": rec.get("notes", ""),
    }


def reindex_one(rec):
    idx = read_index()
    idx[rec["name"]] = index_entry(rec)
    write_index(idx)


def reindex_all():
    idx = {}
    for name in all_names():
        try:
            idx[name] = index_entry(load(name))
        except Exception as exc:
            idx[name] = {"name": name, "error": str(exc)}
    write_index(idx)
    return idx


# --------------------------------------------------------------------------- audit

def audit(action, name="-", detail="", ok=True):
    line = {
        "ts": _now(),
        "who": caller(),
        "action": action,
        "secret": name,
        "ok": ok,
        "detail": detail,
        "cwd": os.getcwd(),
        "pid": os.getpid(),
        "session": os.environ.get("CLAUDE_CODE_SESSION_ID", ""),
    }
    try:
        try:
            if os.path.getsize(AUDIT) > 5 * 1024 * 1024:
                os.replace(AUDIT, AUDIT + ".1")
        except OSError:
            pass
        fd = os.open(AUDIT, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.write(json.dumps(line) + "\n")
            fcntl.flock(fh, fcntl.LOCK_UN)
    except Exception:
        pass


# -------------------------------------------------------------------------- policy

DEFAULT_POLICY = {
    "agent_denied_commands": [
        "get", "show", "export", "add", "edit", "set", "rm", "identity",
        "_values", "import", "hide", "unhide", "rename", "ui", "keyring",
    ],
    "allow": ["*"],
    "deny": [],
}


def policy():
    try:
        with open(POLICY) as fh:
            p = json.load(fh)
        for k, v in DEFAULT_POLICY.items():
            p.setdefault(k, v)
        # Denials are the union of the vault's list and the built-in one. A
        # vault created before a command was denied should pick the denial up,
        # and a union can only ever add refusals — never drop one the file
        # asked for.
        p["agent_denied_commands"] = sorted(
            set(p.get("agent_denied_commands", ()))
            | set(DEFAULT_POLICY["agent_denied_commands"]))
        return p
    except Exception:
        return dict(DEFAULT_POLICY)


def check_access(name):
    """Raise Denied if the caller may not touch `name`."""
    import fnmatch
    p = policy()
    if not is_agent():
        return
    for pat in p.get("deny", []):
        if fnmatch.fnmatch(name, pat):
            audit("denied-policy", name, "matched deny %s" % pat, ok=False)
            raise Denied("policy denies agent access to %s" % name)
    if not any(fnmatch.fnmatch(name, pat) for pat in p.get("allow", ["*"])):
        audit("denied-policy", name, "not in allow", ok=False)
        raise Denied("policy does not allow agent access to %s" % name)


def guard_mode():
    try:
        with open(GUARD) as fh:
            m = fh.read().strip()
        return m if m in ("on", "warn", "off") else "on"
    except Exception:
        return "on"


def set_guard(mode):
    fd = os.open(GUARD, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(mode)


# ---------------------------------------------------------------------- structure

def classify(value):
    s = str(value)
    if re.fullmatch(r"[0-9]+", s):
        return "digits"
    if re.fullmatch(r"[0-9a-f]+", s) and len(s) >= 16:
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9]+", s):
        return "base62"
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        return "base64url"
    if re.fullmatch(r"[\x20-\x7e]+", s):
        return "ascii"
    return "binary/utf8"


def hidden_fields(rec):
    """The set of field names this record masks in `peek`.

    With no explicit choice, everything populated is masked except the
    addressing fields — so a field nobody anticipated is hidden, not leaked.
    """
    h = rec.get("hidden", None)
    if h is not None:
        return set(h)
    populated = {f for f, v in rec.get("fields", {}).items() if v not in (None, "")}
    populated |= set(rec.get("extra", {}).keys())
    return (populated - DEFAULT_PUBLIC) | (DEFAULT_HIDDEN & populated)


def preview(field, value, chars=4, hide=True):
    """Structure of one field: enough to verify format, never enough to use."""
    if value in (None, ""):
        return "(empty)"
    s = str(value)
    if not hide:
        return "%s   [%d chars, %s]" % (s, len(s), classify(s))
    # hidden field: leading chars only, and never more than a quarter of it
    n = max(0, min(chars, len(s) // 4))
    head = s[:n]
    return "%s%s   [%d chars, %s]" % (head, "•" * min(12, len(s) - n),
                                      len(s), classify(s))


def secret_values(rec):
    """Live secret values of a record — for the leak-redaction backstop only."""
    out = []
    for f in hidden_fields(rec):
        v = rec["fields"].get(f)
        if v and len(str(v)) >= 8:
            out.append(str(v))
    for v in rec.get("extra", {}).values():
        if isinstance(v, str) and len(v) >= 12:
            out.append(v)
    return out
