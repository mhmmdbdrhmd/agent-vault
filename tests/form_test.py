"""Form behaviour: type-driven default fields, and the Save/Cancel buttons.

Changing the type must offer that type's usual fields — ssh wants host, port,
username, key — without ever discarding something already typed.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)
import sys

import vltlib as V      # noqa: E402
import vltui            # noqa: E402

fails = []


def check(label, ok, detail=""):
    print("%-5s %s%s" % ("ok " if ok else "FAIL", label,
                         "" if ok else "   " + str(detail)[:110]))
    if not ok:
        fails.append(label)


def blank_form(rtype="token", rows=None):
    f = vltui.Form.__new__(vltui.Form)
    f.original = None
    f.orig_name = None
    f.name = "test/formcheck"
    f.rtype = rtype
    f.account = ""
    f.notes = ""
    f.msg = ""
    f.cur = 1
    f.rows = rows if rows is not None else [
        vltui.FieldRow(x, "", x not in V.DEFAULT_PUBLIC)
        for x in vltui.TYPE_FIELDS[rtype]]
    return f


def names(f):
    return [r.name for r in f.rows]


# Every type has a sensible default set, drawn from the schema vocabulary.
for t in V.TYPES:
    check("type %s has defaults" % t, bool(vltui.TYPE_FIELDS.get(t)))
    bad = [f for f in vltui.TYPE_FIELDS[t] if f not in V.FIELDS]
    check("type %s uses schema fields" % t, not bad, bad)

# token -> ssh brings in the ssh fields.
f = blank_form("token")
f._apply_type_defaults("ssh")
check("ssh gets host/port/username",
      {"host", "port", "username"} <= set(names(f)), names(f))
check("ssh keeps a key field", "key" in names(f) or "password" in names(f))
check("type recorded", f.rtype == "ssh")

# An empty default from the old type is dropped when the new type drops it.
f = blank_form("ssh")
f._apply_type_defaults("token")
check("empty ssh fields cleared on switch to token",
      "port" not in names(f), names(f))
check("token field present", "token" in names(f))

# ...but anything typed is never lost.
f = blank_form("ssh")
for r in f.rows:
    if r.name == "password":
        r.value = "typed-secret"
f._apply_type_defaults("token")
check("typed value survives a type change", "password" in names(f), names(f))
check("typed value itself intact",
      any(r.name == "password" and r.value == "typed-secret" for r in f.rows))

# ...and neither is a field already stored on an edited record.
f = blank_form("ssh", rows=[vltui.FieldRow("host", "", False, existing=True),
                            vltui.FieldRow("port", "", False, existing=True)])
f._apply_type_defaults("token")
check("stored fields survive a type change",
      {"host", "port"} <= set(names(f)), names(f))

# Ordering follows the new type, so the form reads sensibly.
f = blank_form("token")
f._apply_type_defaults("ssh")
order = names(f)
check("fields ordered by the type's list",
      order.index("host") < order.index("username"), order)

# Masking defaults: addressing fields visible, everything else masked.
f = blank_form("token")
f._apply_type_defaults("ssh")
byname = {r.name: r for r in f.rows}
check("host not masked by default", not byname["host"].hidden)
check("port not masked by default", not byname["port"].hidden)
check("password masked by default", byname["password"].hidden)
check("key masked by default", byname["key"].hidden)

# Buttons occupy their own rows, after notes.
f = blank_form("login")
check("save row after notes", f._i_save() == f._i_notes() + 1)
check("cancel row after save", f._i_cancel() == f._i_save() + 1)
check("row count covers the buttons", f._n_rows() == f._i_cancel() + 1)

# Save refuses an invalid branch and an empty record, with a message.
f = blank_form("login")
f.name = "Bad Name"
check("invalid branch blocks save", f._try_save() is None)
check("invalid branch explains why", "branch" in f.msg.lower(), f.msg)

f = blank_form("login")
f.msg = ""
check("empty record blocks save", f._try_save() is None)
check("empty record explains why", "empty" in f.msg.lower(), f.msg)

f = blank_form("login")
f.rows[0].value = "someone"
rec = f._try_save()
check("valid form saves", rec is not None and rec["name"] == "test/formcheck")
check("saved record carries the type", rec and rec["type"] == "login")

print()
print("all clear" if not fails else "%d FAILURE(S): %s" % (len(fails), fails))
sys.exit(1 if fails else 0)
