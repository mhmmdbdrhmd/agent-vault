"""End-to-end tests of `vlt exec` — the hook cannot see these, only the CLI can.

Injecting a secret into a child process is only safe if the child consumes it.
A child whose job is to print its environment turns injection into disclosure.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)
import os
import subprocess
import sys

SECRET = TH.FIXTURE

TH.init_vault()
TH.make_fixture()
VAR = "GITHUB_TOKEN"

# The value must never appear in stdout/stderr of any of these.
CASES = [
    ("env dumper",           ["env"],                                  "DENY"),
    ("printenv",             ["printenv"],                             "DENY"),
    ("printenv VAR",         ["printenv", VAR],                        "DENY"),
    ("set",                  ["set"],                                  "DENY"),
    ("proc environ",         ["cat", "/proc/self/environ"],            "DENY"),
    ("shell interpolation",  ["sh", "-c", "echo $" + VAR],             "DENY"),
    ("braced interpolation", ["sh", "-c", "echo ${" + VAR + "}"],      "DENY"),
    ("env in pipeline",      ["sh", "-c", "env | grep TOKEN"],         "DENY"),
    ("consumer reads env",   ["python3", "-c",
                              "import os;print(len(os.environ['" + VAR + "']))"],
                                                                       "ALLOW"),
    ("plain command",        ["true"],                                 "ALLOW"),
]

env = TH.AGENT

# Fetch the real value once, as a human, so we can assert it never leaks.
val = TH.vlt(["get", SECRET, "token"]).stdout.strip()

fails = []
for label, cmd, want in CASES:
    r = subprocess.run(["vlt", "exec", SECRET, "--"] + cmd,
                       capture_output=True, text=True, env=env)
    blocked = r.returncode == 16
    got = "DENY" if blocked else "ALLOW"
    leaked = bool(val) and (val in r.stdout or val in r.stderr)
    ok = (got == want) and not leaked
    if not ok:
        fails.append((label, got, leaked))
    print("%-5s %-22s %-6s%s" % ("ok " if ok else "FAIL", label, got,
                                 "  LEAKED VALUE" if leaked else ""))

print()
if fails:
    print("%d FAILURE(S)" % len(fails))
    for label, got, leaked in fails:
        print("   %-22s got=%s leaked=%s" % (label, got, leaked))
else:
    print("all clear: no env-dump path, no value in any output")
sys.exit(1 if fails else 0)
