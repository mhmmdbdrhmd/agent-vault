"""Credentials that span lines: SSH keys, certificates, service-account blobs.

Every reader in this program once assumed a credential was one line. That
assumption failed three different ways, and the third was not a truncation bug
at all:

  * the plain prompt used getpass(), which stops at the first newline AND
    restores the terminal with TCSAFLUSH — discarding the rest of the paste, so
    a key became its own armour header with nothing to show that anything was
    lost;

  * input(), used for the unmasked fields, does not flush, so the tail of a
    pasted key became the answers to the following prompts — and `notes` is
    printed in full by `vlt peek`;

  * the curses form returned from edit_line on the first newline and handed
    every remaining character to the FORM's key handler. In the record browser
    `d` is delete, `v` is reveal and `q` is quit, and a base64 key body
    contains all three. That is not lossy input; it is the program typing
    commands into itself.

These assertions pin all three, plus the byte that makes a stored key usable:
OpenSSH rejects a key whose final -----END----- has no newline after it.
"""

import os
import pty
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                       # noqa: E402

sys.path.insert(0, TH.REPO)
import vltlib as V                                         # noqa: E402
import vltui                                               # noqa: E402

fails = []


def check(label, ok, detail=""):
    print("%-5s %s%s" % ("ok " if ok else "FAIL", label,
                         "" if ok else "   " + str(detail)[:200]))
    if not ok:
        fails.append(label)


TH.init_vault()

# Not a key. The armour lines are assembled from parts so that no secret
# scanner in the pipeline reports this repository as leaking a private key — a
# scanner whose findings are all known-and-ignored is a scanner nobody reads.
BEGIN = "-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5
END = "-" * 5 + "END OPENSSH PRIVATE KEY" + "-" * 5
BODY = ["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB",
        "AAAAMwAAAAtzc2gtZWQyNTUxOQAAACBFWFhBTVBMRW5vdGFrZXlF",
        "WEFNUExFbm90YWtleUVYQU1QTEUAAAAJZXhhbXBsZWtleQECAwQ="]
KEYTEXT = "\n".join([BEGIN] + BODY + [END])

# The body deliberately contains the characters that are commands in the
# browser, because that is the hazard being tested.
assert set("dvq") <= set("".join(BODY).lower()), "body must contain d, v, q"


# ------------------------------------------------------------------ 1. helpers
check("armour is recognised", V.is_armoured(KEYTEXT))
check("a password is not armour", not V.is_armoured("hunter2"))
check("armour with CRLF is still armour",
      V.is_armoured(KEYTEXT.replace("\n", "\r\n")))
check("normalise adds the terminating newline",
      V.normalise_multiline(KEYTEXT) == KEYTEXT + "\n")
check("normalise folds CRLF",
      "\r" not in V.normalise_multiline(KEYTEXT.replace("\n", "\r\n")))
check("normalise leaves a password alone",
      V.normalise_multiline("pw\rwith\rcr") == "pw\rwith\rcr")
check("key is a declared multi-line field", "key" in V.MULTILINE_FIELDS)


# ---------------------------------------------------- 2. the non-interactive path
r = subprocess.run([sys.executable, TH.VLT, "set", "ssh/pipe", "key", "-"],
                   input=KEYTEXT, capture_output=True, text=True, env=TH.HUMAN)
rec = V.load("ssh/pipe") if V.exists("ssh/pipe") else {"fields": {}}
check("`vlt set … -` stores the whole key",
      rec["fields"].get("key") == KEYTEXT + "\n",
      "%r / %s" % (rec["fields"].get("key"), r.stderr))


# ------------------------------------------------------- 3. the plain prompt path
def prompt_paste(name, fields, typed, plain=True, wait=2.5):
    """Drive `vlt _prompt` through a pty and return the saved record."""
    import json
    payload = os.path.join(TH.VLT_HOME, "spec-%s.json" % name.replace("/", "-"))
    with open(payload, "w") as fh:
        json.dump({"name": name, "type": "ssh", "fields": fields}, fh)
    env = dict(TH.HUMAN)
    env["TERM"] = "xterm-256color"
    env["LINES"], env["COLUMNS"] = "40", "100"
    if plain:
        env["VLT_PLAIN_PROMPT"] = "1"
    else:
        env.pop("VLT_PLAIN_PROMPT", None)
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(sys.executable, [sys.executable, TH.VLT, "_prompt", payload],
                  env)
    out = b""
    try:
        time.sleep(1.0)
        for chunk, pause in typed:
            os.write(fd, chunk)
            time.sleep(pause)
        deadline = time.time() + wait
        os.set_blocking(fd, False)
        while time.time() < deadline:
            try:
                out += os.read(fd, 65536)
            except (OSError, BlockingIOError):
                pass
            time.sleep(0.05)
    finally:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
    return out.decode("utf-8", "replace")


screen = prompt_paste("ssh/prompt", ["key"],
                      [((KEYTEXT + "\n").encode(), 1.5), (b"\n\n", 1.0)])
rec = V.load("ssh/prompt") if V.exists("ssh/prompt") else {"fields": {},
                                                           "notes": "?"}
check("the prompt keeps every line of a pasted key",
      rec["fields"].get("key") == KEYTEXT + "\n",
      "stored %d chars, pasted %d" % (len(rec["fields"].get("key") or ""),
                                      len(KEYTEXT)))
check("no part of the key leaked into `notes`",
      not (rec.get("notes") or "").strip(), repr(rec.get("notes")))
check("no part of the key leaked into `account`",
      not (rec.get("account") or "").strip(), repr(rec.get("account")))
check("the pasted key was never echoed to the screen",
      BODY[0] not in screen)

# A plain one-line value must still finish on one Enter — a reader that waits
# for an -----END----- that is never coming is a hang, not a fix.
started = time.time()
screen = prompt_paste("token/plain", ["token"],
                      [(b"EXAMPLEtokenAAAABBBBCCCCDDDD\n", 0.6), (b"\n\n", 0.6)],
                      wait=1.5)
took = time.time() - started
rec = V.load("token/plain") if V.exists("token/plain") else {"fields": {}}
check("a one-line value still commits on Enter, promptly (%.1fs)" % took,
      rec["fields"].get("token") == "EXAMPLEtokenAAAABBBBCCCCDDDD" and took < 8,
      repr(rec["fields"].get("token")))


# --------------------------------------------------- 4. what `vlt file` writes
out = os.path.join(TH.VLT_HOME, "written.key")
subprocess.run([sys.executable, TH.VLT, "file", "ssh/pipe", "key",
                "--out", out, "--mode", "0600"],
               capture_output=True, text=True, env=TH.HUMAN)
written = open(out).read() if os.path.exists(out) else ""
check("`vlt file` terminates an armoured value", written.endswith("\n"))
check("`vlt file` writes the key unchanged otherwise",
      written == KEYTEXT + "\n")
check("the written key file is 0600",
      os.path.exists(out) and (os.stat(out).st_mode & 0o777) == 0o600)

TH.vlt(["set", "test/pw", "password", "no-newline-please"], env=TH.HUMAN)
out2 = os.path.join(TH.VLT_HOME, "written.txt")
subprocess.run([sys.executable, TH.VLT, "file", "test/pw", "password",
                "--out", out2], capture_output=True, text=True, env=TH.HUMAN)
check("`vlt file` does NOT add a newline to a password",
      open(out2).read() == "no-newline-please")


# ------------------------------------------------- 5. the paste parser, in units
class StubWin(object):
    """A window that plays back a scripted byte stream to getch()."""

    def __init__(self, data):
        self.q = list(data)
        self.blocking = True

    def getch(self):
        if self.q:
            return self.q.pop(0)
        return -1 if not self.blocking else -1

    def nodelay(self, v):
        self.blocking = not v

    def timeout(self, v):
        pass

    def keypad(self, v):
        pass

    def getmaxyx(self):
        return (40, 100)


def seq(text):
    return [27, 91, 50, 48, 48, 126] + list(text.encode()) + \
           [27, 91, 50, 48, 49, 126]


w = StubWin(seq(KEYTEXT))
k = vltui.read_key(w)
check("a bracketed paste is recognised as one event", k == vltui.PASTE_KEY)
check("the paste carries its whole text", vltui.take_paste() == KEYTEXT)

w = StubWin([ord("d")])
check("an ordinary keypress is still an ordinary keypress",
      vltui.read_key(w) == ord("d"))

w = StubWin([27])
check("a bare ESC is still ESC", vltui.read_key(w) == 27)

w = StubWin(list(b"AAAA\nBBBB"))
check("drain_pending returns what is already queued",
      vltui.drain_pending(w) == "AAAA\nBBBB")

w = StubWin([])
check("drain_pending returns nothing when nobody pasted",
      vltui.drain_pending(w) == "")


# ------------------------------------------- 6. the form, driven through a pty
screen = prompt_paste(
    "ssh/form", ["key"],
    [(b"\x1b[B" * 3, 0.8),          # down to the `key` row
     (b"\n", 0.6),                  # start editing it
     ((KEYTEXT + "\n").encode(), 1.5),
     (b"\x04", 0.5),                # ^D commits the field
     (b"\x1b[B" * 2, 0.6),          # down to [Save]
     (b"\n", 1.2)],
    plain=False, wait=2.0)
rec = V.load("ssh/form") if V.exists("ssh/form") else None
check("the form saves a pasted key whole",
      rec is not None and rec["fields"].get("key") == KEYTEXT + "\n",
      "saved=%s stored=%r" % (rec is not None,
                              (rec or {}).get("fields", {}).get("key")))
check("the form never echoed the key body", BODY[0] not in screen)


# ------------------- 6b. a multi-line paste into a field that is NOT multi-line
# The realistic accident: a key pasted into `password`, or a value that simply
# wraps. There is no armour to detect here, so the only thing standing between
# the second line and the `notes` field is the drain-on-Enter fallback.
TWOLINE = "EXAMPLEfirstlineAAAA\nEXAMPLEsecondlineBBBB"

screen = prompt_paste("test/wrapped", ["password"],
                      [((TWOLINE + "\n").encode(), 1.5), (b"\n\n", 1.0)])
rec = V.load("test/wrapped") if V.exists("test/wrapped") else {"fields": {}}
check("an unarmoured multi-line paste is kept whole",
      rec["fields"].get("password") == TWOLINE,
      repr(rec["fields"].get("password")))
check("its second line did not become `account`",
      not (rec.get("account") or "").strip(), repr(rec.get("account")))
check("its second line did not become `notes`",
      not (rec.get("notes") or "").strip(), repr(rec.get("notes")))

# And the same through the form, where `token` is a single-line field: the
# paste arrives as bare keystrokes because a pty does not bracket anything.
screen = prompt_paste(
    "test/formwrapped", ["token"],
    [(b"\x1b[B" * 3, 0.8),
     (b"\n", 0.6),
     ((TWOLINE + "\n").encode(), 1.5),
     (b"\x04", 0.5),
     (b"\x1b[B" * 2, 0.6),
     (b"\n", 1.2)],
    plain=False, wait=2.0)
rec = V.load("test/formwrapped") if V.exists("test/formwrapped") else None
check("the form keeps a multi-line paste in a single-line field",
      rec is not None and rec["fields"].get("token") == TWOLINE,
      "saved=%s stored=%r" % (rec is not None,
                              (rec or {}).get("fields", {}).get("token")))
check("the form did not run the tail of that paste as commands",
      rec is not None and rec["name"] == "test/formwrapped",
      "name is %r" % ((rec or {}).get("name"),))


# ------------------------------- 7. a paste in the BROWSER must not run as keys
def browse_paste(payload_bytes):
    """Open `vlt ui`, paste into the tree view, then quit. Returns the screen."""
    env = dict(TH.HUMAN)
    env["TERM"] = "xterm-256color"
    env["LINES"], env["COLUMNS"] = "40", "100"
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(sys.executable, [sys.executable, TH.VLT, "ui"], env)
    out = b""
    try:
        time.sleep(1.5)
        os.write(fd, payload_bytes)
        time.sleep(2.0)
        os.write(fd, b"q")
        time.sleep(0.8)
        os.set_blocking(fd, False)
        for _ in range(20):
            try:
                out += os.read(fd, 65536)
            except (OSError, BlockingIOError):
                pass
            time.sleep(0.05)
    finally:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
    return out.decode("utf-8", "replace")


before = sorted(V.index().keys()) if hasattr(V, "index") else None
marked = ("\x1b[200~" + KEYTEXT + "\x1b[201~").encode()
screen = browse_paste(marked)
after = sorted(V.index().keys()) if before is not None else None
check("a paste into the browser deletes nothing",
      before is None or before == after,
      "%s -> %s" % (before, after))
check("a paste into the browser reveals nothing", BODY[0] not in screen)
clean = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", screen)
check("the browser says it ignored the paste",
      "ignored here" in clean or "paste" in clean.lower(), clean[-300:])

print()
print("all clear" if not fails else "%d FAILURE(S): %s" % (len(fails), fails))
sys.exit(1 if fails else 0)
