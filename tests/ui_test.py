"""TUI: tree construction, and a real render under a pseudo-terminal.

curses code fails at runtime, not import time, so the smoke test drives the real
program through a pty and checks it draws and exits cleanly.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)
import os
import pty
import select
import subprocess
import sys
import time

import vltlib as V          # noqa: E402
import vltui               # noqa: E402

fails = []


def check(label, ok, detail=""):
    print("%-5s %s%s" % ("ok " if ok else "FAIL", label,
                         "" if ok else "   " + str(detail)[:120]))
    if not ok:
        fails.append(label)



# The UI needs something to draw. Build a small synthetic tree in the throwaway
# vault — never rely on whatever happens to be in the caller's real one.
TH.init_vault()
for _name, _fields in [
    ("vps/senko/3x-ui", [("username", "exampleuser"),
                         ("password", "EXAMPLE-password-0000")]),
    ("vps/senko/ssh", [("host", "198.51.100.10"), ("port", "22"),
                       ("username", "exampleuser")]),
    ("vps/frankfurt/3x-ui", [("username", "exampleuser"),
                             ("password", "EXAMPLE-password-1111")]),
    ("cloudflare/example", [("token", "EXAMPLE-token-2222222222")]),
]:
    for _f, _v in _fields:
        TH.vlt(["set", _name, _f, _v])

# ------------------------------------------------------------ tree structure
names = ["vps/senko/3x-ui", "vps/senko/ssh", "vps/frankfurt/3x-ui",
         "cloudflare/biss", "test/dummy"]
root = vltui.build_tree(names)
flat = vltui.flatten(root)
paths = [n.path for n in flat]

check("branches created", "vps" in paths and "vps/senko" in paths)
check("leaves marked as records",
      all(n.is_record for n in flat if n.path in names))
check("branches not marked as records",
      not any(n.is_record for n in flat if n.path in ("vps", "vps/senko")))
check("depth is segment count",
      all(n.depth == n.path.count("/") for n in flat))
check("every record reachable", all(p in paths for p in names))

# collapsing hides descendants
for n in flat:
    if n.path == "vps/senko":
        n.expanded = False
collapsed = [x.path for x in vltui.flatten(root)]
check("collapse hides children", "vps/senko/3x-ui" not in collapsed)
check("collapse keeps the branch", "vps/senko" in collapsed)
check("collapse leaves siblings", "vps/frankfurt/3x-ui" in collapsed)

# search
hits = [n.path for n in vltui.flatten(root, query="senko")]
check("search finds matches", "vps/senko" in hits)
check("search excludes non-matches", "cloudflare/biss" not in hits)

# ------------------------------------------------------- record construction
form = vltui.Form.__new__(vltui.Form)
form.original = None            # constructing a NEW record, not editing
form.orig_name = None
form.name = "vps/testbox/panel"
form.rtype = "vpn"
form.account = "acct"
form.notes = "note"
form.rows = [
    vltui.FieldRow("username", "admin", False),
    vltui.FieldRow("password", "pw12345678", True),
    vltui.FieldRow("API_token", "tok12345678", True),
]
rec = form._record()
check("canonical field stored in fields", rec["fields"]["username"] == "admin")
check("unknown field stored in extra", rec["extra"]["API_token"] == "tok12345678")
check("hidden set from checkboxes",
      set(rec["hidden"]) == {"password", "API_token"})
check("public field not hidden", "username" not in rec["hidden"])
check("env_map built", any(v == "password" for v in rec["env_map"].values()))
check("type carried", rec["type"] == "vpn")

# ------------------------------------------------------------- pty smoke test
def drive(keys, cols=100, rows=30, settle=0.45):
    """Run `vlt ui` in a pty, send keys, return what it drew."""
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["LINES"] = str(rows)
        os.environ["COLUMNS"] = str(cols)
        os.environ["TERM"] = "xterm-256color"
        os.environ.update(TH.HUMAN)
        os.environ["VLT_TEST_CONFIRM"] = "1"
        os.execv(sys.executable, [sys.executable, TH.VLT, "ui"])
    out = b""
    time.sleep(settle)
    for k in keys:
        os.write(fd, k)
        time.sleep(0.16)
        while select.select([fd], [], [], 0.1)[0]:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                break
            out += chunk
    try:
        os.write(fd, b"q")
    except OSError:
        pass
    time.sleep(0.3)
    while select.select([fd], [], [], 0.2)[0]:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    import signal
    deadline = time.time() + 6
    status = None
    while time.time() < deadline:
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            break
        time.sleep(0.1)
    if status is None:
        try:
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
        except OSError:
            status = 0
    os.close(fd)
    return out.decode("utf-8", "replace"), os.WEXITSTATUS(status)


# NOTE: navigation and rendering only. Never send SPACE / d / m here — those
# mutate real records, and an accidental unmask prints a live secret.
screen, rc = drive([b"", b"\x1b[B", b"\x1b[B", b"\x1b[C", b"\t"])
check("ui exits cleanly", rc == 0, "exit=%d" % rc)
check("ui drew its title", "credential vault" in screen)
check("ui drew the tree", "vps" in screen or "cloudflare" in screen)
check("ui drew the help bar", "pane" in screen)
check("no traceback", "Traceback" not in screen, screen[-400:])

# Arrow keys must navigate, not quit: an unresolved ESC [ B used to exit.
screen_nav, rc_nav = drive([b"\x1b[B"] * 6)
check("arrows navigate rather than quit",
      rc_nav == 0 and "Traceback" not in screen_nav)
check("detail pane renders a record after navigating",
      "FIELD" in screen_nav and "STATE" in screen_nav, screen_nav[-300:])
check("values are masked in the detail pane",
      "\u2022" in screen_nav, "no mask glyph found")

# The add form must open and validate the branch name.
screen_form, rc_form = drive([b"a", b"\x1b"])
check("add form opens", "new credential" in screen_form, screen_form[-300:])
check("add form asks for a branch", "branch" in screen_form)
check("add form shows the hidden column", "HIDDEN" in screen_form)
check("add form shows a Save button", "Save" in screen_form, screen_form[-300:])
check("add form shows a Cancel button", "Cancel" in screen_form)
check("add form exits cleanly", rc_form == 0)

# `e` must open the edit form on the selected record.
screen_edit, rc_edit = drive([b"\x1b[B"] * 6 + [b"e", b"\x1b"])
check("edit form opens on a record", "edit " in screen_edit, screen_edit[-300:])
check("edit form exits cleanly", rc_edit == 0)

# A narrow terminal must not crash the renderer.
screen2, rc2 = drive([b"\x1b[B", b"\t"], cols=40, rows=12)
check("survives a narrow terminal", rc2 == 0 and "Traceback" not in screen2,
      screen2[-400:])

print()
print("all clear" if not fails else "%d FAILURE(S): %s" % (len(fails), fails))
sys.exit(1 if fails else 0)
