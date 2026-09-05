"""Per-record hidden-field selection.

The masked set is the user's choice, per record — not a fixed list. An agent
must be able to read the structure but never change what is masked.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)
import os
import sys

SECRET = TH.FIXTURE

TH.init_vault()
TH.make_fixture()
HUMAN = TH.HUMAN
AGENT = TH.AGENT


def run(args, env):
    return TH.vlt(args, env=env)


def peek(env=AGENT):
    return run(["peek", SECRET], env).stdout


fails = []


def check(label, cond):
    print("%-5s %s" % ("ok " if cond else "FAIL", label))
    if not cond:
        fails.append(label)


# Baseline: default hidden set masks token, shows username.
run(["hide", SECRET, "--none"], HUMAN)
run(["hide", SECRET, "password,token,key,secret"], HUMAN)
out = peek()
check("default: token masked", TH.FIXTURE_TOKEN[:12] not in out and TH.FIXTURE_TOKEN[:4] in out)
check("default: username shown", TH.FIXTURE_USER in out)

# The user hides a field that the old fixed list treated as public.
run(["hide", SECRET, "username"], HUMAN)
out = peek()
check("user hid username -> masked", TH.FIXTURE_USER not in out)
check("username still listed", "username:" in out)

# ...and reveals one the old list always masked.
run(["unhide", SECRET, "token"], HUMAN)
out = peek()
check("user unhid token -> shown in full",
      TH.FIXTURE_TOKEN in out)

# --all / --none
run(["hide", SECRET, "--all"], HUMAN)
out = peek()
check("--all masks everything",
      TH.FIXTURE_USER not in out and TH.FIXTURE_TOKEN[:16] not in out)

run(["hide", SECRET, "--none"], HUMAN)
out = peek()
check("--none reveals everything", TH.FIXTURE_USER in out)

# An agent must not be able to change the masking.
r = run(["hide", SECRET, "--none"], AGENT)
check("agent cannot hide", r.returncode != 0)
r = run(["unhide", SECRET, "token"], AGENT)
check("agent cannot unhide", r.returncode != 0)

# Unknown field names are rejected rather than silently stored.
r = run(["hide", SECRET, "nosuchfield"], HUMAN)
check("unknown field rejected", r.returncode != 0)

# Restore the default for anything that runs after this.
run(["hide", SECRET, "--none"], HUMAN)
run(["hide", SECRET, "password,token,key,secret"], HUMAN)
out = peek()
check("restored: token masked again", TH.FIXTURE_TOKEN[:16] not in out)

print()
print("all clear" if not fails else "%d FAILURE(S): %s" % (len(fails), fails))
sys.exit(1 if fails else 0)
