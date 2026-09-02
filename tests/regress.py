
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)
import json, subprocess, sys

HOOK = TH.HOOK
H = os.path.expanduser("~")

# Regression: a reader verb in one segment must not taint another segment.
CASES = [
    # The hardened rule drops the reader-verb list entirely: naming a credential
    # file at all is enough to deny, whatever the verb — rm and mv included.
    ("rm -f /tmp/x/.env && python3 -c 'print(1)'", "DENY"),
    ("rm -f ./app.env; echo done", "DENY"),
    ("ls " + H + "/claude && python3 script.py", "ALLOW"),
    ("echo hi; cat " + H + "/.ssh/id_" + "rsa", "DENY"),
    ("python3 -c 'x=1' && cat " + H + "/.net" + "rc", "DENY"),
    ("cp " + H + "/.aws/creden" + "tials /tmp/steal", "DENY"),
    ("git status && npm install", "ALLOW"),
    # moving a credential file is blocked by design: it can stage one for
    # reading somewhere the guard does not cover.
    ("mv " + H + "/proj/.env " + H + "/proj/.env.bak", "DENY"),
    ("head -c 40 " + H + "/proj/.env", "DENY"),
]

fails = 0
for cmd, want in CASES:
    ev = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
    r = subprocess.run([sys.executable, HOOK], input=ev,
                       capture_output=True, text=True,
                       env=TH.AGENT)
    got = "DENY" if '"deny"' in r.stdout else "ALLOW"
    ok = got == want
    fails += not ok
    print("%-5s want=%-6s got=%-6s %s" % ("ok " if ok else "FAIL", want, got, cmd[:58]))

print("\n%d/%d passed" % (len(CASES) - fails, len(CASES)))
sys.exit(1 if fails else 0)
