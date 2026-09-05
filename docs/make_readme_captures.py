#!/usr/bin/env python3
"""Generate every terminal block in the README from a real run.

    python3 docs/make_readme_captures.py            # print them
    python3 docs/make_readme_captures.py --write    # write docs/captures/

Nothing here is typed by hand. The vault is a throwaway in a temp directory
holding invented records, so the output is real output about fake secrets —
which is the only combination that is both checkable and safe to publish.

The UI block is a genuine screen: the curses program is driven through a
pseudo-terminal and the emulator's grid is dumped, so what the README shows is
what the program drew.
"""

import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VLT = os.path.join(REPO, "vlt")

DEMO = [
    ("vps/alpha/ssh", "ssh",
     [("host", "198.51.100.10"), ("port", "22"), ("username", "deploy"),
      ("password", "EXAMPLE-not-a-real-password")]),
    ("vps/alpha/panel", "service",
     [("username", "admin"), ("url", "https://198.51.100.10:2053/example"),
      ("token", "EXAMPLEpanelTOKEN0123456789abcdef")]),
    ("vps/beta/ssh", "ssh",
     [("host", "198.51.100.20"), ("port", "22"), ("username", "deploy"),
      ("password", "EXAMPLE-also-not-real")]),
    ("github.com/example", "token",
     [("username", "exampleuser"),
      ("token", "ghp_EXAMPLE0000000000000000000000000000")]),
    ("openai.com/example", "apikey",
     [("key", "sk-EXAMPLE-not-a-real-openai-key")]),
    ("cloudflare/example", "token",
     [("token", "EXAMPLEcfTOKEN000000000000000000000000")]),
]


def build(root):
    env = dict(os.environ)
    env.update({"VLT_HOME": root, "VLT_ALLOW_FILE_KEY": "1",
                "VLT_NO_KEYRING": "1", "VLT_HUMAN": "1",
                "VLT_TEST_CONFIRM": "1",
                "PYTHONPATH": REPO + os.pathsep + env.get("PYTHONPATH", "")})
    env.pop("CLAUDECODE", None)
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    subprocess.run([sys.executable, VLT, "init"], env=env,
                   capture_output=True, check=True)
    for name, rtype, fields in DEMO:
        for field, value in fields:
            # --type is honoured when the record is created, so it goes on
            # every set; later ones are no-ops rather than a second guess.
            subprocess.run([sys.executable, VLT, "set", name, field, value,
                            "--type", rtype],
                           env=env, capture_output=True, check=True)
    return env


def run(env, *args, agent=True):
    e = dict(env)
    if agent:
        e["CLAUDECODE"] = "1"
        e.pop("VLT_HUMAN", None)
        e.pop("VLT_TEST_CONFIRM", None)
    r = subprocess.run([sys.executable, VLT] + list(args), env=e,
                       capture_output=True, text=True)
    return (r.stdout + r.stderr).rstrip("\n")


def ui_screen(env, cols=96, rows=22):
    """Drive the real curses UI through a pty and dump what it drew."""
    try:
        import pyte
    except ImportError:
        return None
    screen = pyte.Screen(cols, rows)
    stream = pyte.ByteStream(screen)
    pid, fd = pty.fork()
    if pid == 0:                                    # child: the UI itself
        os.environ.update(env)
        os.environ["TERM"] = "xterm-256color"
        os.environ["LINES"] = str(rows)
        os.environ["COLUMNS"] = str(cols)
        os.execv(sys.executable, [sys.executable, VLT, "ui"])
    # Walk down to a record so the detail pane has something in it: the empty
    # pane is the honest first frame, but it shows none of what the UI does.
    keys = b"\x1b[B" * 8
    sent = False
    deadline = time.time() + 8
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.3)
        if not r:
            if not sent:
                os.write(fd, keys)
                sent = True
                time.sleep(0.4)
                continue
            break
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        stream.feed(data)
    try:
        os.write(fd, b"q")
        time.sleep(0.3)
        os.close(fd)
    except OSError:
        pass
    try:
        os.waitpid(pid, os.WNOHANG)
    except OSError:
        pass
    lines = [l.rstrip() for l in screen.display]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def main():
    root = tempfile.mkdtemp(prefix="vlt-demo-")
    try:
        env = build(root)
        blocks = [
            ("list", run(env, "list")),
            ("peek", run(env, "peek", "github.com/example")),
            ("peek-panel", run(env, "peek", "vps/alpha/panel")),
            ("audit", run(env, "audit", "--tail", "6")),
            ("denied", run(env, "get", "github.com/example", "token")),
        ]
        ui = ui_screen(env)
        if ui:
            blocks.insert(0, ("ui", ui))
        else:
            print("(pyte not installed — the UI capture was skipped)",
                  file=sys.stderr)

        if "--write" in sys.argv:
            out = os.path.join(REPO, "docs", "captures")
            os.makedirs(out, exist_ok=True)
            for name, text in blocks:
                with open(os.path.join(out, name + ".txt"), "w") as fh:
                    fh.write(text + "\n")
            print("wrote %d capture(s) to docs/captures/" % len(blocks))
        else:
            for name, text in blocks:
                print("=" * 78)
                print("== %s" % name)
                print("=" * 78)
                print(text)
                print()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
