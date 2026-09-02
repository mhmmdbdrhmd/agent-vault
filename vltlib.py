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
import stat
import sys
import time
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

def _use_keyring():
    """False when the caller has opted out — tests, or a deliberate file key."""
    return os.environ.get("VLT_NO_KEYRING") != "1"


def _keyring_get():
    if not _use_keyring():
        return None
    import secretstorage
    conn = secretstorage.dbus_init()
    try:
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked():
            coll.unlock()
        for item in coll.search_items(KEYRING_ATTRS):
            return item.get_secret()
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _keyring_set(raw):
    if not _use_keyring():
        raise RuntimeError("keyring disabled by VLT_NO_KEYRING")
    import secretstorage
    conn = secretstorage.dbus_init()
    try:
        coll = secretstorage.get_default_collection(conn)
        if coll.is_locked():
            coll.unlock()
        for item in coll.search_items(KEYRING_ATTRS):
            item.delete()
        coll.create_item(KEYRING_LABEL, KEYRING_ATTRS, raw, replace=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass


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
                raise Denied(
                    "no Secret Service keyring is available%s.\n"
                    "     vlt keeps its master key in the keyring so that it is "
                    "not a readable file.\n"
                    "     Without one, the key must live in %s at mode 0400, "
                    "which is a\n"
                    "     weaker model: anything running as you can read it "
                    "directly.\n"
                    "     If you accept that, re-run with "
                    "VLT_ALLOW_FILE_KEY=1."
                    % ((": " + err) if err else "", FALLBACK_KEY))
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
        "_values", "import", "hide", "unhide",
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
