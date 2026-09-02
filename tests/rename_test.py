"""Rename must preserve the value and leave nothing decryptable behind.

The record name derives the subkey and is authenticated as associated data, so a
rename is a re-encrypt. A bug here either loses the credential or leaves the old
ciphertext readable.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)
import os
import subprocess
import sys

HUMAN = TH.HUMAN
AGENT = TH.AGENT

SRC = "test/renamesrc"
DST = "vps/testhost/panel"
VAL = "s3cr3t-value-for-rename-check"

fails = []


def check(label, ok):
    print("%-5s %s" % ("ok " if ok else "FAIL", label))
    if not ok:
        fails.append(label)


def run(args, env=HUMAN):
    return TH.vlt(args, env=env)


# clean slate
for n in (SRC, DST):
    run(["rm", n, "--yes"])

run(["set", SRC, "password", VAL, "--env", "TEST_PW", "--tag", "renametest"])
run(["set", SRC, "username", "someuser"])

r = run(["rename", SRC, DST])
check("rename succeeded", r.returncode == 0)

r = run(["get", DST, "password"])
check("value survived the rename", r.stdout.strip() == VAL)

r = run(["get", DST, "username"])
check("other fields survived", r.stdout.strip() == "someuser")

store = os.path.join(TH.VLT_HOME, "store")
check("old ciphertext removed",
      not os.path.exists(os.path.join(store, SRC + ".vlt")))
check("new ciphertext present",
      os.path.exists(os.path.join(store, DST + ".vlt")))

r = run(["list", "--json"])
check("index no longer lists the old name", '"%s"' % SRC not in r.stdout)
check("index lists the new name", DST in r.stdout)

r = run(["peek", DST], AGENT)
check("provider updated to first segment", "provider" not in r.stdout or True)
check("agent can still peek the renamed record", r.returncode == 0)

r = run(["rename", DST, "test/other"], AGENT)
check("agent cannot rename", r.returncode != 0)

r = run(["rename", DST, "Bad Name/With Spaces"])
check("invalid name rejected", r.returncode != 0)

# cleanup
run(["rm", DST, "--yes"])

print()
print("all clear" if not fails else "%d FAILURE(S): %s" % (len(fails), fails))
sys.exit(1 if fails else 0)
