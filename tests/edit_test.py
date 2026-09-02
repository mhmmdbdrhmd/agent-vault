"""Editing an existing record.

The rule that matters: a blank value means "keep what is stored", so changing
the type or the masking of one field never forces you to retype a secret.
Removing a row must actually drop the field, including its env_map entry.

Uses a throwaway record. Never point these at a live one — a failure here
prints values.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)
import os
import subprocess
import sys

import vltlib as V      # noqa: E402
import vltui            # noqa: E402

REC = "test/edittarget"
HUMAN = TH.HUMAN

fails = []


def check(label, ok, detail=""):
    print("%-5s %s%s" % ("ok " if ok else "FAIL", label,
                         "" if ok else "   " + str(detail)[:100]))
    if not ok:
        fails.append(label)


def fresh():
    TH.vlt(["rm", REC, "--yes"], env=HUMAN)
    rec = V.blank_record(REC, "login")
    rec["fields"]["username"] = "olduser"
    rec["fields"]["password"] = "oldpassword123"
    rec["fields"]["host"] = "10.0.0.1"
    rec["extra"]["API_token"] = "oldtoken456"
    rec["env_map"] = {"X_USERNAME": "username", "X_PASSWORD": "password",
                      "X_HOST": "host", "X_API_TOKEN": "API_token"}
    rec["account"] = "acct"
    rec["notes"] = "old note"
    V.save(rec)
    return V.load(REC)


def form_for(rec, rows, name=None, rtype=None, account=None, notes=None):
    f = vltui.Form.__new__(vltui.Form)
    f.original = rec
    f.orig_name = rec["name"]
    f.name = name if name is not None else rec["name"]
    f.rtype = rtype if rtype is not None else rec["type"]
    f.account = account if account is not None else rec.get("account", "")
    f.notes = notes if notes is not None else rec.get("notes", "")
    f.rows = rows
    return f


# 1. Blank values keep what is stored.
rec = fresh()
rows = [vltui.FieldRow("username", "", False, existing=True),
        vltui.FieldRow("password", "", True, existing=True),
        vltui.FieldRow("host", "", False, existing=True),
        vltui.FieldRow("API_token", "", True, existing=True)]
out = form_for(rec, rows, rtype="ssh").run.__self__._record()
check("blank keeps stored password", out["fields"]["password"] == "oldpassword123")
check("blank keeps stored extra", out["extra"]["API_token"] == "oldtoken456")
check("type change applied", out["type"] == "ssh")

# 2. A typed value replaces the stored one.
rec = fresh()
rows = [vltui.FieldRow("username", "newuser", False),
        vltui.FieldRow("password", "", True, existing=True),
        vltui.FieldRow("host", "", False, existing=True),
        vltui.FieldRow("API_token", "", True, existing=True)]
out = form_for(rec, rows)._record()
check("typed value replaces", out["fields"]["username"] == "newuser")
check("other fields untouched", out["fields"]["password"] == "oldpassword123")

# 3. A removed row drops the field and its env_map entry.
rec = fresh()
rows = [vltui.FieldRow("username", "", False, existing=True),
        vltui.FieldRow("password", "", True, existing=True)]
out = form_for(rec, rows)._record()
check("dropped canonical field cleared", out["fields"]["host"] is None)
check("dropped extra field removed", "API_token" not in out["extra"])
check("env_map entry for dropped field removed",
      "X_HOST" not in out["env_map"] and "X_API_TOKEN" not in out["env_map"])
check("kept env_map entries survive", out["env_map"].get("X_PASSWORD") == "password")

# 4. Masking comes from the checkboxes.
rec = fresh()
rows = [vltui.FieldRow("username", "", True, existing=True),
        vltui.FieldRow("password", "", False, existing=True),
        vltui.FieldRow("host", "", False, existing=True),
        vltui.FieldRow("API_token", "", True, existing=True)]
out = form_for(rec, rows)._record()
check("checkbox sets hidden", set(out["hidden"]) == {"username", "API_token"})

# 5. Editing the branch renames; the caller deletes the old path.
rec = fresh()
rows = [vltui.FieldRow("username", "", False, existing=True)]
out = form_for(rec, rows, name="test/movedtarget")._record()
check("branch change carried", out["name"] == "test/movedtarget")
check("provider recomputed", out["provider"] == "test")

# 6. Account and notes are editable and optional.
rec = fresh()
rows = [vltui.FieldRow("username", "", False, existing=True)]
out = form_for(rec, rows, account="", notes="")._record()
check("empty account keeps stored", out["account"] == "acct")
out = form_for(fresh(), rows, account="newacct", notes="new note")._record()
check("account updated", out["account"] == "newacct")
check("notes updated", out["notes"] == "new note")

TH.vlt(["rm", REC, "--yes"], env=HUMAN)
TH.vlt(["rm", "test/movedtarget", "--yes"], env=HUMAN)

print()
print("all clear" if not fails else "%d FAILURE(S): %s" % (len(fails), fails))
sys.exit(1 if fails else 0)
