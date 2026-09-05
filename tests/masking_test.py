"""Masking must fail closed.

The original default hid a fixed list, so any field the schema had not
anticipated — `API_token`, `reality`, a webhook URL — was printed in full. The
default is now: hide everything except addressing fields.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)
import os
import sys

HUMAN = TH.HUMAN
AGENT = TH.AGENT

REC = "test/masking"

# Synthetic throughout. Never paste a real value into a test: test files get
# committed, and a fixture is forever.
SECRETS = {
    "API_token": "EXAMPLE-api-token-0000000000000000000000000000",
    "reality":   "EXAMPLE-reality-key-000000000000000000",
    "panel":     "https://198.51.100.10:8443/EXAMPLE-secret-path/",
    "password":  "EXAMPLE-password-0000",
}
PUBLIC = {"username": "exampleuser", "host": "198.51.100.10", "port": "8443"}

fails = []


def check(label, ok):
    print("%-5s %s" % ("ok " if ok else "FAIL", label))
    if not ok:
        fails.append(label)


def run(a, env=HUMAN):
    return TH.vlt(a, env=env)


run(["rm", REC, "--yes"])
for k, v in {**SECRETS, **PUBLIC}.items():
    run(["set", REC, k, v])

out = run(["peek", REC], AGENT).stdout

for k, v in SECRETS.items():
    check("%s masked" % k, v not in out)
    check("%s still listed by name" % k, k + ":" in out)

for k, v in PUBLIC.items():
    check("%s shown (addressing)" % k, v in out)

# A url is a secret by default: panel/webhook URLs carry secret paths.
run(["rm", REC, "--yes"])
run(["set", REC, "url", "https://hooks.example.com/T00/B11/XXXXsecretXXXX"])
out = run(["peek", REC], AGENT).stdout
check("url masked by default", "XXXXsecretXXXX" not in out)

# An explicit choice still wins over the default.
run(["hide", REC, "--none"])
out = run(["peek", REC], AGENT).stdout
check("explicit --none still reveals", "XXXXsecretXXXX" in out)

run(["rm", REC, "--yes"])
print()
print("all clear" if not fails else "%d FAILURE(S): %s" % (len(fails), fails))
sys.exit(1 if fails else 0)
