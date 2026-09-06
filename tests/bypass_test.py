"""The VLT_HUMAN bypass: an env var is not proof that a person is present.

The guard hook reads Bash command text but not file contents, so an agent can
hide a forbidden command inside a script. The CLI must therefore not trust
VLT_HUMAN on its own.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)
import os
import stat
import subprocess
import sys
import tempfile

SECRET = TH.FIXTURE

TH.init_vault()
TH.make_fixture()
VAL = TH.FIXTURE_TOKEN

AGENT = TH.AGENT

fails = []


def check(label, ok, extra=""):
    print("%-5s %s%s" % ("ok " if ok else "FAIL", label, extra))
    if not ok:
        fails.append(label)


d = tempfile.mkdtemp(prefix="vlt-bypass-")

# 1. The direct route: agent runs a denied subcommand.
r = TH.vlt(["get", SECRET, "token"], env=AGENT)
check("direct `get` refused", r.returncode != 0 and VAL not in r.stdout)

# 2. The bypass: hide it in a script the hook cannot read.
script = os.path.join(d, "innocent_build_step.sh")
with open(script, "w") as fh:
    fh.write("#!/bin/sh\nVLT_HUMAN=1 vlt get %s token\n" % SECRET)
os.chmod(script, os.stat(script).st_mode | stat.S_IEXEC)

r = subprocess.run(["sh", script], capture_output=True, text=True, env=AGENT)
check("script with VLT_HUMAN=1 refused",
      r.returncode != 0 and VAL not in r.stdout,
      "" if VAL not in r.stdout else "   LEAKED VALUE")

# 3. Same trick for unhide, which would make peek reveal everything.
script2 = os.path.join(d, "step2.sh")
with open(script2, "w") as fh:
    fh.write("#!/bin/sh\nVLT_HUMAN=1 vlt unhide %s token\n" % SECRET)
r = subprocess.run(["sh", script2], capture_output=True, text=True, env=AGENT)
check("script `unhide` refused", r.returncode != 0)

# 4. And the masking really did not change.
r = TH.vlt(["peek", SECRET], env=AGENT)
check("token still masked after the attempt", VAL not in r.stdout)

# 5. A real terminal is still allowed (simulated by the test escape hatch).
env_ok = {**AGENT, "VLT_HUMAN": "1", "VLT_TEST_CONFIRM": "1"}
r = TH.vlt(["get", SECRET, "token"], env=env_ok)
check("confirmed human still works", r.returncode == 0 and VAL in r.stdout)

# 6. And it refuses PROMPTLY. With no terminal and no desktop, vlt must decide
# on its own rather than wait for an answer that is not coming. This is the
# assertion that would have caught the macOS dialog hang: every check above
# passes just as well when the command takes a minute and a half.
import subprocess                                        # noqa: E402
import time                                              # noqa: E402

for cmd in (["rename", SECRET, "test/elsewhere"], ["get", SECRET, "token"],
            ["ui"]):
    started = time.time()
    try:
        r = subprocess.run([sys.executable, TH.VLT] + cmd, env=AGENT,
                           capture_output=True, text=True, timeout=20)
        took = time.time() - started
        check("`%s` refused, and promptly (%.1fs)" % (cmd[0], took),
              r.returncode != 0 and took < 10)
    except subprocess.TimeoutExpired:
        check("`%s` refused, and promptly" % cmd[0], False,
              "hung for 20s waiting for a prompt nothing can answer")

print()
print("all clear" if not fails else "%d FAILURE(S): %s" % (len(fails), fails))
sys.exit(1 if fails else 0)
