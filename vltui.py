"""vltui — terminal UI for the vlt vault.

A tree of records on the left, the selected record's fields on the right, and a
per-field hide toggle. Also provides the form used when an agent asks for a
credential, so the person entering it can move the record in the tree and choose
what stays masked before anything is written.

curses only: no third-party dependency, so the vault stays self-contained.
"""

import curses
import sys

import vltlib as V

# ------------------------------------------------------------------ constants

C_DIM = 1
C_SEL = 2
C_HID = 3
C_PUB = 4
C_HEAD = 5
C_WARN = 6
C_OK = 7

HELP_MAIN = ("↑↓ move   ←→ fold   TAB pane   SPACE mask/unmask   "
             "v reveal   e edit   a add   m move   d delete   / find   q quit")
HELP_SHORT = "↑↓ move  TAB pane  SPACE mask  e edit  a add  q quit"
HELP_FORM = ("↑↓ row   ENTER edit/press   SPACE hide/show   + add field   "
             "- drop field   ESC cancel")

# The fields each credential type normally needs. Choosing a type fills these
# in; anything already typed is kept.
TYPE_FIELDS = {
    "login":    ["username", "password"],
    "token":    ["token"],
    "apikey":   ["key"],
    "oauth":    ["username", "token", "secret", "url"],
    "ssh":      ["host", "port", "username", "password", "key"],
    "database": ["host", "port", "username", "password", "path"],
    "cert":     ["key", "path"],
    "vpn":      ["host", "port", "username", "password"],
    "smtp":     ["host", "port", "username", "password"],
    "service":  ["username", "password", "token", "url"],
}


def _init_colors():
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(C_SEL, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(C_HID, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_PUB, curses.COLOR_GREEN, -1)
    curses.init_pair(C_HEAD, curses.COLOR_CYAN, -1)
    curses.init_pair(C_WARN, curses.COLOR_RED, -1)
    curses.init_pair(C_OK, curses.COLOR_GREEN, -1)


def _cp(n):
    return curses.color_pair(n) if curses.has_colors() else 0


def _put(win, y, x, text, attr=0, maxw=None):
    """Write text, clipped to the window. curses raises on overflow."""
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    limit = (w - x - 1) if maxw is None else min(maxw, w - x - 1)
    if limit <= 0:
        return
    try:
        win.addnstr(y, x, str(text), limit, attr)
    except curses.error:
        pass


# ---------------------------------------------------------------------- tree

class Node:
    def __init__(self, label, path, is_record, depth):
        self.label = label
        self.path = path
        self.is_record = is_record
        self.depth = depth
        self.children = []
        self.expanded = True


def build_tree(names):
    root = Node("", "", False, -1)
    index = {"": root}
    for name in sorted(names):
        parts = name.split("/")
        for i in range(len(parts)):
            path = "/".join(parts[:i + 1])
            if path in index:
                continue
            parent = index["/".join(parts[:i])] if i else root
            node = Node(parts[i], path, i == len(parts) - 1, i)
            parent.children.append(node)
            index[path] = node
    # A path can be both a branch and a record; the record wins for display.
    for name in names:
        if name in index:
            index[name].is_record = True
    return root


def flatten(node, out=None, query=""):
    if out is None:
        out = []
    for ch in node.children:
        if query:
            hit = query.lower() in ch.path.lower()
            sub = []
            flatten(ch, sub, query)
            if not hit and not sub:
                continue
            out.append(ch)
            out.extend(sub)
            continue
        out.append(ch)
        if ch.expanded and ch.children:
            flatten(ch, out, query)
    return out


# ------------------------------------------------------------------- editing


# Terminals send arrows as ESC [ A. ncurses usually assembles that into KEY_UP,
# but only if the bytes arrive inside escdelay. When they do not, getch()
# returns a bare ESC and the tail leaks through as separate keypresses. Reading
# the tail ourselves makes the UI behave the same either way.
_ESC_SEQ = {
    (91, 65): curses.KEY_UP,    (79, 65): curses.KEY_UP,
    (91, 66): curses.KEY_DOWN,  (79, 66): curses.KEY_DOWN,
    (91, 67): curses.KEY_RIGHT, (79, 67): curses.KEY_RIGHT,
    (91, 68): curses.KEY_LEFT,  (79, 68): curses.KEY_LEFT,
    (91, 72): curses.KEY_HOME,  (79, 72): curses.KEY_HOME,
    (91, 70): curses.KEY_END,   (79, 70): curses.KEY_END,
}


# A key code that cannot collide with a real one. The text that came with it
# is held here rather than returned, so that callers comparing the result to
# ints (`32 <= k < 127`) keep working unchanged.
PASTE_KEY = 0x7E000
_PASTE = []

_PASTE_BEGIN = [91, 50, 48, 48, 126]                 # ESC [ 2 0 0 ~
_PASTE_END = [27, 91, 50, 48, 49, 126]               # ESC [ 2 0 1 ~


def set_bracketed_paste(on):
    """Ask the terminal to mark pasted text, and put it back on the way out.

    A terminal that does not understand the request ignores it, which leaves
    the drain-on-Enter fallback in edit_line as the safety net.
    """
    try:
        sys.stdout.write("\x1b[?2004h" if on else "\x1b[?2004l")
        sys.stdout.flush()
    except Exception:
        pass


def take_paste():
    """The text of the paste that PASTE_KEY was returned for."""
    return _PASTE.pop() if _PASTE else ""


def _collect_paste(win, limit=1 << 18):
    """Everything up to the ESC[201~ that closes a bracketed paste."""
    out = []
    win.nodelay(False)
    win.timeout(400)               # a paste arrives in a burst, not by hand
    try:
        while len(out) < limit:
            c = win.getch()
            if c == -1:
                break              # the terminal stopped mid-paste
            out.append(c)
            if out[-6:] == _PASTE_END:
                del out[-6:]
                break
    finally:
        win.timeout(-1)
    raw = bytes(c & 0xFF for c in out if 0 <= c < 256)
    text = raw.decode("utf-8", "replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


# How long to wait for the next character before deciding a paste has ended.
# Above the gap between bytes of a paste (microseconds, even chunked across a
# pty) and below the gap between two deliberate keypresses (~100ms+).
PASTE_WINDOW_MS = 60


def drain_pending(win, limit=1 << 18, window=PASTE_WINDOW_MS):
    """Whatever the terminal is still delivering, as text.

    The fallback for terminals without bracketed paste. A paste does not cross
    a pty atomically, so asking only for what is buffered RIGHT NOW returns
    before the rest of it has arrived — and the remainder then reaches the key
    handler, which is the failure this exists to prevent. Waiting a short
    window per character catches the whole burst. A real Enter costs one
    window and returns empty.
    """
    out = []
    win.timeout(window)
    try:
        while len(out) < limit:
            c = win.getch()
            if c == -1:
                break
            out.append(c)
    finally:
        win.timeout(-1)
    if out[:5] == _PASTE_BEGIN:                 # a paste the parser missed
        del out[:5]
    if out[-6:] == _PASTE_END:
        del out[-6:]
    raw = bytes(c & 0xFF for c in out if 0 <= c < 256)
    return raw.decode("utf-8", "replace").replace("\r\n", "\n").replace(
        "\r", "\n")


def read_key(win):
    """getch(), with escape sequences resolved by hand as a fallback."""
    k = win.getch()
    if k != 27:
        return k
    win.nodelay(True)
    try:
        a = win.getch()
        if a == -1:
            return 27                      # a real ESC press
        b = win.getch()
        if b == -1:
            return 27
        if a == 91 and b == 50:            # ESC [ 2 ... — paste, or Insert
            rest = [win.getch(), win.getch(), win.getch()]
            if [a, b] + rest == [91, 50] + _PASTE_BEGIN[2:]:
                _PASTE.append(_collect_paste(win))
                return PASTE_KEY
            return -1
        if (a, b) in _ESC_SEQ:
            return _ESC_SEQ[(a, b)]
        if a == 91 and 48 <= b <= 57:      # ESC [ n ~
            tail = win.getch()
            if b == 51 and tail == 126:
                return curses.KEY_DC
            return -1
        return -1                          # unknown sequence: ignore it
    finally:
        win.nodelay(False)


def _summarise(buf, masked):
    """How a value that spans lines is shown in a one-line field."""
    text = "".join(buf)
    n = text.count("\n") + 1
    return "<%d lines, %d chars%s>" % (n, len(text), ", hidden" if masked else "")


def edit_line(win, y, x, width, initial="", masked=False, multiline=False,
              hint_y=None):
    """A field editor. Returns the new text, or None on ESC.

    Single-line unless told otherwise, but it will not LOSE a multi-line value:
    a paste that spans lines promotes the field, and an armoured value ends
    itself at its -----END----- line. Ctrl-D commits from any mode.
    """
    buf = list(initial)
    pos = len(buf)
    multi = multiline or "\n" in initial
    curses.curs_set(1)
    win.keypad(True)

    def _done():
        # The newline a paste ends with is punctuation, not part of the value:
        # a password committed with a trailing "\n" simply fails to
        # authenticate. An armoured value gets exactly one back when it is
        # saved — see vltlib.normalise_multiline.
        return "".join(buf).rstrip("\n")

    def _armour_complete():
        """An armoured value that has reached its END line is finished."""
        text = _done()
        if not V.is_armoured(text):
            return False
        lines = [ln for ln in text.split("\n") if ln.strip()]
        return bool(lines) and bool(V.PEM_END_RE.match(lines[-1]))

    try:
        while True:
            if multi:
                shown = _summarise(buf, masked)
            else:
                shown = ("•" * len(buf)) if masked else _done()
            if len(shown) > width - 1:
                shown = shown[-(width - 1):]
            _put(win, y, x, shown.ljust(width - 1), _cp(C_SEL), width - 1)
            if hint_y is not None:
                h, w = win.getmaxyx()
                tip = ("Enter = new line   ^D = done   ESC = cancel"
                       if multi else
                       "Enter = done   ^D = done   ESC = cancel")
                _put(win, hint_y, 1, tip.ljust(w - 2), _cp(C_DIM), w - 2)
            try:
                win.move(y, x + min(pos, width - 2))
            except curses.error:
                pass
            win.refresh()
            k = read_key(win)
            if k == PASTE_KEY:
                text = take_paste()
                if "\n" in text:
                    multi = True
                for ch in text:
                    buf.insert(pos, ch)
                    pos += 1
                if _armour_complete():
                    return _done()
                continue
            if k in (27,):                       # ESC
                return None
            if k == 4:                           # ^D commits, in any mode
                return _done()
            if k in (10, 13, curses.KEY_ENTER):
                if multi:
                    buf.insert(pos, "\n")
                    pos += 1
                    if _armour_complete():
                        return _done()
                    continue
                # Single-line, Enter pressed. If the terminal handed us more
                # input in the same burst this was a paste it did not bracket:
                # folding it into the value is the whole point — otherwise it
                # escapes into the form's key handler and runs as commands.
                pending = drain_pending(win)
                if pending:
                    multi = True
                    for ch in "\n" + pending:
                        buf.insert(pos, ch)
                        pos += 1
                    if _armour_complete():
                        return _done()
                    continue
                return _done()
            if k in (curses.KEY_BACKSPACE, 127, 8):
                if pos:
                    del buf[pos - 1]
                    pos -= 1
            elif k == curses.KEY_DC:
                if pos < len(buf):
                    del buf[pos]
            elif k == curses.KEY_LEFT:
                pos = max(0, pos - 1)
            elif k == curses.KEY_RIGHT:
                pos = min(len(buf), pos + 1)
            elif k == curses.KEY_HOME:
                pos = 0
            elif k == curses.KEY_END:
                pos = len(buf)
            elif k == 21:                        # ^U clear
                buf, pos = [], 0
            elif 32 <= k < 127:
                buf.insert(pos, chr(k))
                pos += 1
    finally:
        curses.curs_set(0)


def confirm(win, question):
    h, w = win.getmaxyx()
    _put(win, h - 2, 0, " " * (w - 1))
    _put(win, h - 2, 0, "%s  [y/N] " % question, _cp(C_WARN) | curses.A_BOLD)
    win.refresh()
    k = win.getch()
    return k in (ord("y"), ord("Y"))


# ---------------------------------------------------------------------- form

class FieldRow:
    def __init__(self, name, value="", hidden=True, existing=False):
        self.name = name
        self.value = value
        self.hidden = hidden
        self.existing = existing        # already stored: blank means "keep"


class Form:
    """Add or edit one record: branch (name), type, account, fields, masking."""

    def __init__(self, stdscr, name="", rtype="token", fields=None,
                 account="", notes="", reason="", rows=None,
                 title="new credential", original=None):
        self.s = stdscr
        self.title = title
        self.reason = reason
        self.original = original          # editing: the stored record
        self.orig_name = name if original else None
        self.name = name
        self.rtype = rtype if rtype in V.TYPES else "token"
        self.account = account
        self.notes = notes
        self.rows = rows if rows is not None else [
            FieldRow(f, "", f not in V.DEFAULT_PUBLIC) for f in (fields or [])]
        if not self.rows:
            self.rows = [FieldRow("username", "", False),
                         FieldRow("password", "", True)]
        self.cur = 0
        self.msg = ""

    # Row order: branch, type, account, <fields...>, notes, Save, Cancel.
    def _i_notes(self):
        return 3 + len(self.rows)

    def _i_save(self):
        return self._i_notes() + 1

    def _i_cancel(self):
        return self._i_notes() + 2

    def _n_rows(self):
        return self._i_cancel() + 1

    def _valid(self):
        return bool(V.NAME_RE.match(self.name))

    def _apply_type_defaults(self, new_type):
        """Swap in the new type's usual fields, never dropping typed values."""
        wanted = TYPE_FIELDS.get(new_type, [])
        old_wanted = set(TYPE_FIELDS.get(self.rtype, []))
        kept = []
        for r in self.rows:
            # Anything the user filled in, or that is already stored, stays.
            if r.value or r.existing or r.name not in old_wanted:
                kept.append(r)
        have = {r.name for r in kept}
        for f in wanted:
            if f not in have:
                kept.append(FieldRow(f, "", f not in V.DEFAULT_PUBLIC))
        order = {f: i for i, f in enumerate(wanted)}
        kept.sort(key=lambda r: order.get(r.name, len(order)))
        self.rows = kept or [FieldRow("username", "", False)]
        self.rtype = new_type
        self.cur = min(self.cur, self._n_rows() - 1)

    def draw(self):
        self.s.erase()
        h, w = self.s.getmaxyx()
        _put(self.s, 0, 1, " %s " % self.title,
             _cp(C_HEAD) | curses.A_BOLD | curses.A_REVERSE)
        if self.reason:
            _put(self.s, 1, 1, "reason: %s" % self.reason, _cp(C_DIM))

        y = 3
        ok = self._valid()
        self._row(y, "branch", self.name or "(required)", 0,
                  extra="" if ok else "  ◀ like vps/alpha/3x-ui", bad=not ok)
        y += 1
        self._row(y, "type", self.rtype, 1,
                  extra="   ←→ changes the type and its usual fields")
        y += 1
        self._row(y, "account", self.account or "(optional label)", 2,
                  extra="   which identity, when a provider has several")
        y += 2

        _put(self.s, y, 3, "%-16s %-26s %s" % ("FIELD", "VALUE", "HIDDEN"),
             _cp(C_DIM) | curses.A_BOLD)
        y += 1
        self._fields_y = y
        for i, r in enumerate(self.rows):
            sel = self.cur == 3 + i
            if r.value:
                shown = "•" * min(len(r.value), 18) if r.hidden else r.value[:26]
            else:
                shown = "(kept)" if r.existing else "(empty)"
            box = "[x]" if r.hidden else "[ ]"
            _put(self.s, y, 1, " %-16s %-26s %s  %s" % (
                r.name, shown, box,
                "masked" if r.hidden else "shown in full"),
                _cp(C_SEL) if sel else 0)
            y += 1

        y += 1
        self._notes_y = y
        self._row(y, "notes", self.notes or "(optional, never a secret)",
                  self._i_notes())
        y += 2

        save_ok = ok and any(r.value or r.existing for r in self.rows)
        self._button(y, 2, "  Save  ", self.cur == self._i_save(), save_ok)
        self._button(y, 14, " Cancel ", self.cur == self._i_cancel(), True)
        _put(self.s, y, 26,
             "ENTER on a button   (^S also saves, if your terminal allows it)",
             _cp(C_DIM))
        y += 2
        _put(self.s, y, 1,
             "Hidden fields still show name, length and first characters —",
             _cp(C_DIM))
        _put(self.s, y + 1, 1,
             "enough for an agent to check the format, never enough to use.",
             _cp(C_DIM))

        if self.msg:
            _put(self.s, h - 3, 1, self.msg, _cp(C_WARN))
        _put(self.s, h - 1, 0, HELP_FORM.ljust(w - 1)[:w - 1],
             _cp(C_DIM) | curses.A_REVERSE)
        self.s.refresh()

    def _button(self, y, x, label, selected, enabled):
        if selected:
            attr = _cp(C_SEL) | curses.A_BOLD
        elif enabled:
            attr = _cp(C_OK) | curses.A_BOLD
        else:
            attr = _cp(C_DIM)
        _put(self.s, y, x, "[%s]" % label, attr)

    def _row(self, y, label, value, idx, extra="", bad=False):
        sel = self.cur == idx
        attr = _cp(C_SEL) if sel else (_cp(C_WARN) if bad else 0)
        _put(self.s, y, 1, " %-8s %s" % (label + ":", value), attr)
        if extra:
            _put(self.s, y, 12 + len(str(value)), extra, _cp(C_DIM))

    def _try_save(self):
        if not self._valid():
            self.msg = ("branch must be lowercase "
                        "<provider>/<account>[/<purpose>]")
            return None
        if not any(r.value or r.existing for r in self.rows):
            self.msg = "nothing to save: every field is empty"
            return None
        return self._record()

    def run(self):
        self.s.keypad(True)
        try:
            curses.set_escdelay(25)
        except (AttributeError, curses.error):
            pass
        while True:
            self.draw()
            k = read_key(self.s)
            n = self._n_rows()
            if k == PASTE_KEY:
                # Not a keystroke. Executing the body of a pasted key as
                # commands is exactly the bug this exists to stop.
                text = take_paste()
                self.msg = ("pasted %d chars — press Enter on a field first, "
                            "then paste into it" % len(text))
                continue
            if k == 27:
                return None
            if k in (curses.KEY_UP,) and self.cur > 0:
                self.cur -= 1
            elif k in (curses.KEY_DOWN,) and self.cur < n - 1:
                self.cur += 1
            elif k == 19:                                  # ^S, when it arrives
                rec = self._try_save()
                if rec is not None:
                    return rec
                continue
            elif k == ord(" "):
                if 3 <= self.cur < 3 + len(self.rows):
                    r = self.rows[self.cur - 3]
                    r.hidden = not r.hidden
            elif k in (ord("+"), ord("=")):
                self._add_field()
            elif k == ord("-"):
                if 3 <= self.cur < 3 + len(self.rows) and len(self.rows) > 1:
                    self.rows.pop(self.cur - 3)
                    self.cur = min(self.cur, self._n_rows() - 1)
            elif k in (curses.KEY_LEFT, curses.KEY_RIGHT) and self.cur == 1:
                i = V.TYPES.index(self.rtype)
                nxt = V.TYPES[(i + (1 if k == curses.KEY_RIGHT else -1))
                              % len(V.TYPES)]
                self._apply_type_defaults(nxt)
            elif k in (10, 13, curses.KEY_ENTER):
                if self.cur == self._i_save():
                    rec = self._try_save()
                    if rec is not None:
                        return rec
                    continue
                if self.cur == self._i_cancel():
                    return None
                self._edit_current()
            self.msg = ""

    def _add_field(self):
        h, w = self.s.getmaxyx()
        _put(self.s, h - 2, 0, " " * (w - 1))
        _put(self.s, h - 2, 1, "new field name: ", _cp(C_HEAD))
        self.s.refresh()
        name = edit_line(self.s, h - 2, 17, 30, "")
        if not name:
            return
        low = name.strip().lower()
        if low in V.FIELDS:
            name = low
        self.rows.append(FieldRow(name.strip(), "",
                                  name.strip() not in V.DEFAULT_PUBLIC))
        self.cur = 3 + len(self.rows) - 1

    def _edit_current(self):
        h, w = self.s.getmaxyx()
        i = self.cur
        if i == 0:
            v = edit_line(self.s, 3, 11, min(60, w - 12), self.name)
            if v is not None:
                self.name = v.strip().lower()
        elif i == 2:
            v = edit_line(self.s, 5, 11, min(40, w - 12), self.account)
            if v is not None:
                self.account = v.strip()
        elif 3 <= i < 3 + len(self.rows):
            r = self.rows[i - 3]
            y = getattr(self, "_fields_y", 8) + (i - 3)
            _put(self.s, h - 2, 0, " " * (w - 1))
            multi = r.name in V.MULTILINE_FIELDS
            _put(self.s, h - 2, 1,
                 "value for %s (typing is %s)%s" % (
                     r.name, "hidden" if r.hidden else "visible",
                     " — multi-line: ^D when done" if multi else ""),
                 _cp(C_HEAD))
            v = edit_line(self.s, y, 19, 26, "", masked=r.hidden,
                          multiline=multi, hint_y=h - 1)
            if v is not None and v != "":
                r.value = v
                r.existing = False
        elif i == self._i_notes():
            v = edit_line(self.s, getattr(self, "_notes_y", 10), 11,
                          min(60, w - 12), self.notes)
            if v is not None:
                self.notes = v.strip()

    def _record(self):
        if self.original is not None:
            rec = dict(self.original)
            rec["fields"] = dict(self.original["fields"])
            rec["extra"] = dict(self.original.get("extra", {}))
            rec["env_map"] = dict(self.original.get("env_map", {}))
            # A row removed with `-` means: drop that field from the record.
            keep = {r.name for r in self.rows}
            for f in list(rec["fields"]):
                if rec["fields"][f] not in (None, "") and f not in keep:
                    rec["fields"][f] = None
            for f in list(rec["extra"]):
                if f not in keep:
                    del rec["extra"][f]
            for var, field in list(rec["env_map"].items()):
                if field not in keep:
                    del rec["env_map"][var]
        else:
            rec = (V.load(self.name) if V.exists(self.name)
                   else V.blank_record(self.name, self.rtype))
        rec["name"] = self.name
        rec["type"] = self.rtype
        rec["provider"] = self.name.split("/")[0]
        if self.account:
            rec["account"] = self.account
        if self.notes:
            rec["notes"] = self.notes
        hidden = []
        for r in self.rows:
            if r.hidden:
                hidden.append(r.name)
            if not r.value:
                continue
            if r.name in V.FIELDS:
                rec["fields"][r.name] = r.value
            else:
                rec["extra"][r.name] = r.value
            var = "%s_%s" % (self.name.split("/")[0].split(".")[0].upper()
                             .replace("-", "_"), r.name.upper())
            rec["env_map"].setdefault(var, r.name)
        rec["hidden"] = sorted(set(hidden))
        rec["rotated"] = V._now()
        return rec


# ---------------------------------------------------------------------- app

class App:
    def __init__(self, stdscr):
        self.s = stdscr
        self.query = ""
        self.pane = 0            # 0 tree, 1 detail
        self.sel = 0
        self.fsel = 0
        self.reveal = None
        self.msg = ""
        self.reload()

    def reload(self, keep=None):
        self.index = V.read_index() or V.reindex_all()
        self.root = build_tree(sorted(self.index))
        self.nodes = flatten(self.root, query=self.query)
        if keep:
            for i, n in enumerate(self.nodes):
                if n.path == keep:
                    self.sel = i
                    break
        self.sel = max(0, min(self.sel, len(self.nodes) - 1))

    # -------------------------------------------------------------- drawing
    def current(self):
        if not self.nodes:
            return None
        n = self.nodes[self.sel]
        return n if n.is_record else None

    def draw(self):
        self.s.erase()
        h, w = self.s.getmaxyx()
        split = max(24, min(38, w // 3))

        title = " vlt — credential vault "
        _put(self.s, 0, 0, title.ljust(w - 1),
             _cp(C_HEAD) | curses.A_REVERSE | curses.A_BOLD)
        if self.query:
            _put(self.s, 0, w - 24, " find: %s " % self.query[:14],
                 _cp(C_WARN) | curses.A_REVERSE)

        # tree
        top = max(0, self.sel - (h - 5))
        for i, node in enumerate(self.nodes[top:top + h - 4]):
            y = 2 + i
            idx = top + i
            if node.is_record:
                glyph = "●"
            else:
                glyph = "▾" if node.expanded else "▸"
            label = "%s%s %s" % ("  " * node.depth, glyph, node.label)
            attr = 0
            if idx == self.sel:
                attr = _cp(C_SEL) | (curses.A_BOLD if self.pane == 0 else 0)
            elif not node.is_record:
                attr = _cp(C_DIM)
            _put(self.s, y, 0, label.ljust(split - 1), attr, split - 1)

        for y in range(2, h - 2):
            _put(self.s, y, split - 1, "│", _cp(C_DIM))

        self.draw_detail(split, w, h)

        _put(self.s, h - 2, 0, (self.msg or "")[:w - 1],
             _cp(C_OK) if self.msg.startswith("saved") else _cp(C_WARN))
        bar = HELP_MAIN if w > len(HELP_MAIN) + 2 else HELP_SHORT
        _put(self.s, h - 1, 0, bar.ljust(w - 1)[:w - 1],
             _cp(C_DIM) | curses.A_REVERSE)
        self.s.refresh()

    def draw_detail(self, split, w, h):
        node = self.current()
        x = split + 1
        if node is None:
            _put(self.s, 3, x, "select a record on the left", _cp(C_DIM))
            _put(self.s, 5, x, "a  add a credential here", _cp(C_DIM))
            return
        try:
            rec = V.load(node.path)
        except Exception as exc:
            _put(self.s, 3, x, "cannot read: %s" % exc, _cp(C_WARN))
            return

        hid = V.hidden_fields(rec)
        _put(self.s, 2, x, rec["name"], _cp(C_HEAD) | curses.A_BOLD)
        _put(self.s, 3, x, "type %-10s account %s"
             % (rec["type"], rec.get("account") or "-"), _cp(C_DIM))
        if rec.get("tags"):
            _put(self.s, 4, x, "tags " + ",".join(rec["tags"]), _cp(C_DIM))

        y = 6
        _put(self.s, y, x, "%-13s %-30s %s" % ("FIELD", "VALUE", "STATE"),
             _cp(C_DIM) | curses.A_BOLD)
        y += 1
        self.fields = [(f, rec["fields"][f]) for f in V.FIELDS
                       if rec["fields"].get(f) not in (None, "")]
        self.fields += list(rec.get("extra", {}).items())
        for i, (f, val) in enumerate(self.fields):
            is_hidden = f in hid
            if self.reveal == f:
                shown = str(val)[:30]
                state, sattr = "REVEALED", _cp(C_WARN) | curses.A_BOLD
            else:
                shown = V.preview(f, val, 4, is_hidden).split("   [")[0][:30]
                state = "masked" if is_hidden else "shown"
                sattr = _cp(C_HID) if is_hidden else _cp(C_PUB)
            attr = _cp(C_SEL) if (self.pane == 1 and i == self.fsel) else 0
            _put(self.s, y, x, "%-13s %-30s " % (f, shown), attr)
            _put(self.s, y, x + 45, state, sattr)
            y += 1

        y += 1
        if rec.get("notes"):
            _put(self.s, y, x, "notes: " + rec["notes"][:w - x - 8], _cp(C_DIM))
            y += 2
        _put(self.s, y, x, "SPACE masks/unmasks the selected field",
             _cp(C_DIM))
        _put(self.s, y + 1, x, "v reveals it on screen   e edits this record",
             _cp(C_DIM))

    # ---------------------------------------------------------------- actions
    def toggle_hidden(self):
        node = self.current()
        if not node or not getattr(self, "fields", None):
            return
        rec = V.load(node.path)
        hid = V.hidden_fields(rec)
        f = self.fields[self.fsel][0]
        if f in hid:
            hid.discard(f)
            self.msg = "saved: %s is now shown in full to agents" % f
        else:
            hid.add(f)
            self.msg = "saved: %s is now masked" % f
        rec["hidden"] = sorted(hid)
        V.save(rec)
        V.audit("hide", node.path, "ui toggle %s" % f)

    def do_reveal(self):
        node = self.current()
        if not node or not getattr(self, "fields", None):
            return
        f = self.fields[self.fsel][0]
        if self.reveal == f:
            self.reveal = None
            return
        if confirm(self.s, "Reveal %s of %s on screen?" % (f, node.path)):
            self.reveal = f
            V.audit("reveal", node.path, "ui reveal %s" % f)
            self.msg = "revealed on screen only — press v again to hide"

    def do_add(self, base=""):
        curses.curs_set(0)
        form = Form(self.s, name=base, title="new credential")
        rec = form.run()
        if rec is None:
            self.msg = "cancelled — nothing written"
            return
        V.save(rec)
        V.audit("add", rec["name"], "via ui")
        self.query = ""
        self.reload(keep=rec["name"])
        self.msg = "saved: %s" % rec["name"]


    def do_edit(self):
        node = self.current()
        if not node:
            self.msg = "select a record first — branches hold nothing to edit"
            return
        rec = V.load(node.path)
        hid = V.hidden_fields(rec)
        rows = []
        for f in V.FIELDS:
            if rec["fields"].get(f) not in (None, ""):
                rows.append(FieldRow(f, "", f in hid, existing=True))
        for f in rec.get("extra", {}):
            rows.append(FieldRow(f, "", f in hid, existing=True))
        if not rows:
            rows = [FieldRow("username", "", False)]

        form = Form(self.s, name=node.path, rtype=rec["type"],
                    account=rec.get("account", ""), notes=rec.get("notes", ""),
                    rows=rows, original=rec, title="edit %s" % node.path)
        new = form.run()
        if new is None:
            self.msg = "cancelled — nothing changed"
            return
        V.save(new)
        if form.orig_name and new["name"] != form.orig_name:
            V.delete(form.orig_name)
            V.audit("rename", new["name"], "ui edit from %s" % form.orig_name)
        V.audit("edit", new["name"], "via ui")
        self.query = ""
        self.reload(keep=new["name"])
        self.msg = "saved: %s" % new["name"]

    def do_move(self):
        node = self.current()
        if not node:
            return
        rec = V.load(node.path)
        h, w = self.s.getmaxyx()
        _put(self.s, h - 2, 0, " " * (w - 1))
        _put(self.s, h - 2, 1, "move to branch: ", _cp(C_HEAD))
        self.s.refresh()
        new = edit_line(self.s, h - 2, 17, min(50, w - 18), node.path)
        if not new or new == node.path:
            return
        new = new.strip().lower()
        if not V.NAME_RE.match(new):
            self.msg = "invalid branch: use lowercase provider/account[/purpose]"
            return
        if V.exists(new):
            self.msg = "%s already exists" % new
            return
        rec["name"] = new
        rec["provider"] = new.split("/")[0]
        V.save(rec)
        V.delete(node.path)
        V.audit("rename", new, "ui move from %s" % node.path)
        self.reload(keep=new)
        self.msg = "saved: moved to %s" % new

    def do_delete(self):
        node = self.current()
        if not node:
            return
        if not confirm(self.s, "Delete %s permanently?" % node.path):
            return
        V.delete(node.path)
        V.audit("rm", node.path, "via ui")
        self.reload()
        self.msg = "deleted %s" % node.path

    def do_find(self):
        h, w = self.s.getmaxyx()
        _put(self.s, h - 2, 0, " " * (w - 1))
        _put(self.s, h - 2, 1, "find: ", _cp(C_HEAD))
        self.s.refresh()
        q = edit_line(self.s, h - 2, 7, 30, self.query)
        self.query = "" if q is None else q.strip()
        self.sel = 0
        self.reload()

    # ------------------------------------------------------------------ loop
    def run(self):
        curses.curs_set(0)
        self.s.keypad(True)
        try:
            curses.set_escdelay(25)
        except (AttributeError, curses.error):
            pass
        while True:
            self.draw()
            k = read_key(self.s)
            self.msg = ""
            if k == PASTE_KEY:
                # `d` is delete and `v` is reveal. A base64 key body contains
                # both, so a paste landing here must never be read as keys.
                text = take_paste()
                self.msg = ("pasted %d chars — ignored here; use `a` or `e` "
                            "and paste into a field" % len(text))
                continue
            # ESC is NOT a quit key: an unresolved arrow sequence arrives as
            # ESC, and quitting on it makes the browser unusable.
            if k == ord("q"):
                return
            if k == 27:
                continue
            if k == curses.KEY_RESIZE:
                continue
            if k == 9:                                   # TAB
                self.pane = 1 - self.pane
                self.fsel = 0
            elif k in (curses.KEY_UP, ord("k")):
                if self.pane == 0:
                    self.sel = max(0, self.sel - 1)
                    self.reveal = None
                else:
                    self.fsel = max(0, self.fsel - 1)
                    self.reveal = None
            elif k in (curses.KEY_DOWN, ord("j")):
                if self.pane == 0:
                    self.sel = min(len(self.nodes) - 1, self.sel + 1)
                    self.reveal = None
                else:
                    self.fsel = min(len(getattr(self, "fields", [])) - 1,
                                    self.fsel + 1)
                    self.reveal = None
            elif k in (curses.KEY_RIGHT, ord("l")):
                if self.nodes and not self.nodes[self.sel].is_record:
                    self.nodes[self.sel].expanded = True
                    self.nodes = flatten(self.root, query=self.query)
                elif self.current():
                    self.pane = 1
            elif k in (curses.KEY_LEFT, ord("h")):
                if self.pane == 1:
                    self.pane = 0
                elif self.nodes:
                    self.nodes[self.sel].expanded = False
                    self.nodes = flatten(self.root, query=self.query)
            elif k == ord(" "):
                if self.pane == 1:
                    self.toggle_hidden()
                elif self.nodes and not self.nodes[self.sel].is_record:
                    n = self.nodes[self.sel]
                    n.expanded = not n.expanded
                    self.nodes = flatten(self.root, query=self.query)
            elif k == ord("v"):
                self.pane = 1
                self.do_reveal()
            elif k == ord("a"):
                base = ""
                if self.nodes:
                    n = self.nodes[self.sel]
                    base = (n.path + "/") if not n.is_record else ""
                self.do_add(base)
            elif k == ord("e"):
                self.do_edit()
            elif k == ord("m"):
                self.do_move()
            elif k == ord("d"):
                self.do_delete()
            elif k == ord("/"):
                self.do_find()


# ------------------------------------------------------------------- entries

def _with_paste(fn):
    """Run a curses screen with bracketed paste on, and off again after.

    Leaving the mode set would make every later paste in that terminal arrive
    wrapped in ESC[200~ markers the shell would print literally.
    """
    def wrapped(s):
        set_bracketed_paste(True)
        try:
            return fn(s)
        finally:
            set_bracketed_paste(False)
    return wrapped


def browse():
    return curses.wrapper(
        _with_paste(lambda s: (_init_colors(), App(s).run())[1]))


def request_form(spec):
    """The form an agent's `vlt request` opens. Returns a record or None."""
    def _run(s):
        _init_colors()
        curses.curs_set(0)
        rows = [FieldRow(f, "", f not in V.DEFAULT_PUBLIC)
                for f in spec.get("fields", [])]
        form = Form(s, name=spec.get("name", ""),
                    rtype=spec.get("type", "token"),
                    rows=rows, reason=spec.get("reason", ""),
                    title="credential requested by an agent")
        return form.run()
    return curses.wrapper(_with_paste(_run))
