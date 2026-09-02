"""Form layout: no two rows may share a screen line.

A pty capture suggested the notes row collides with the last field. This checks
the geometry directly, with a stub window that records every write, so the
answer does not depend on terminal diffing.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)
import sys

import vltlib as V      # noqa: E402
import vltui            # noqa: E402

# No real terminal here: colour lookups call into curses, which needs initscr().
vltui._cp = lambda n: 0

fails = []


def check(label, ok, detail=""):
    print("%-5s %s%s" % ("ok " if ok else "FAIL", label,
                         "" if ok else "   " + str(detail)[:160]))
    if not ok:
        fails.append(label)


class StubWin:
    """Records addnstr calls instead of drawing."""

    def __init__(self, h=40, w=100):
        self.h, self.w = h, w
        self.writes = []

    def getmaxyx(self):
        return self.h, self.w

    def erase(self):
        self.writes = []

    def refresh(self):
        pass

    def addnstr(self, y, x, text, n, attr=0):
        self.writes.append((y, x, str(text)[:n]))

    def keypad(self, *_):
        pass

    def move(self, *_):
        pass

    def nodelay(self, *_):
        pass


def layout(rtype):
    win = StubWin()
    f = vltui.Form.__new__(vltui.Form)
    f.s = win
    f.original = None
    f.orig_name = None
    f.name = "test/layout"
    f.rtype = rtype
    f.account = ""
    f.notes = ""
    f.msg = ""
    f.cur = 0
    f.reason = ""
    f.title = "layout check"
    f.rows = [vltui.FieldRow(x, "", x not in V.DEFAULT_PUBLIC)
              for x in vltui.TYPE_FIELDS[rtype]]
    f.draw()
    return f, win


for rtype in V.TYPES:
    f, win = layout(rtype)

    # Which line did each logical row land on?
    field_lines = {}
    notes_line = None
    button_line = None
    for y, x, text in win.writes:
        t = text.strip()
        for r in f.rows:
            if t.startswith(r.name + " ") or t == r.name:
                field_lines.setdefault(r.name, y)
        if t.startswith("notes:"):
            notes_line = y
        if t.startswith("[") and "Save" in t:
            button_line = y

    check("%s: every field drawn" % rtype,
          len(field_lines) == len(f.rows),
          "drew %s of %s" % (len(field_lines), len(f.rows)))
    check("%s: notes drawn" % rtype, notes_line is not None)
    check("%s: buttons drawn" % rtype, button_line is not None)

    if notes_line is not None:
        clash = [n for n, y in field_lines.items() if y == notes_line]
        check("%s: notes does not overlap a field" % rtype, not clash,
              "notes on line %s shared with %s" % (notes_line, clash))
        last_field = max(field_lines.values()) if field_lines else -1
        check("%s: notes below the last field" % rtype,
              notes_line > last_field,
              "notes=%s last field=%s" % (notes_line, last_field))
    if button_line is not None and notes_line is not None:
        check("%s: buttons below notes" % rtype, button_line > notes_line,
              "buttons=%s notes=%s" % (button_line, notes_line))

    lines = sorted(field_lines.values())
    check("%s: fields on distinct lines" % rtype,
          len(set(lines)) == len(lines), lines)

print()
print("all clear" if not fails else "%d FAILURE(S)" % len(fails))
sys.exit(1 if fails else 0)
