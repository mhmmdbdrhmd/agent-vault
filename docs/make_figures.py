#!/usr/bin/env python3
"""Generate the README's figures. Nothing here is hand-drawn.

    python3 docs/make_figures.py            # writes docs/figures/*.svg
    python3 docs/make_figures.py --check    # fail if the committed files differ

Two variants of each figure are produced, light and dark, from one layout and
two palettes, so the README can hand GitHub a <picture> and the diagram stops
being a white rectangle for half the people who open the page.

Everything a box says is a real path, a real command or a real file name. A
diagram that labels things the program does not have is a diagram that will
quietly rot.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "figures")

# Single quotes inside the family names, because these land in a double-quoted
# SVG attribute and a double quote there ends the attribute and the document.
SANS = ("ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI',"
        "Roboto,'Helvetica Neue',Arial,sans-serif")
MONO = ("ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,"
        "'Liberation Mono',monospace")

THEMES = {
    "light": dict(bg="#ffffff", panel="#f6f8fa", panel2="#eaeef2",
                  border="#d0d7de", text="#1f2328", muted="#656d76",
                  accent="#0969da", danger="#cf222e", ok="#1a7f37",
                  key="#8250df", shadow="#00000012"),
    "dark": dict(bg="#0d1117", panel="#161b22", panel2="#1c2128",
                 border="#30363d", text="#e6edf3", muted="#8b949e",
                 accent="#58a6ff", danger="#f85149", ok="#3fb950",
                 key="#a371f7", shadow="#00000040"),
}


# --------------------------------------------------------------- svg primitives

def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


class Canvas(object):
    def __init__(self, w, h, c):
        self.w, self.h, self.c = w, h, c
        self.parts = []

    def add(self, s):
        self.parts.append("  " + s)

    def rect(self, x, y, w, h, fill=None, stroke=None, r=10, width=1.5,
             dash=None):
        d = ' stroke-dasharray="%s"' % dash if dash else ""
        self.add('<rect x="%g" y="%g" width="%g" height="%g" rx="%g" '
                 'fill="%s" stroke="%s" stroke-width="%g"%s/>'
                 % (x, y, w, h, r, fill or "none", stroke or "none", width, d))

    def text(self, x, y, s, size=13, fill=None, anchor="start", family=SANS,
             weight="400", spacing=None, opacity=None):
        extra = ""
        if spacing:
            extra += ' letter-spacing="%g"' % spacing
        if opacity:
            extra += ' opacity="%g"' % opacity
        self.add('<text x="%g" y="%g" font-family="%s" font-size="%g" '
                 'font-weight="%s" fill="%s" text-anchor="%s"%s>%s</text>'
                 % (x, y, family, size, weight, fill or self.c["text"],
                    anchor, extra, esc(s)))

    def line(self, x1, y1, x2, y2, stroke=None, width=1.5, dash=None,
             marker=True):
        d = ' stroke-dasharray="%s"' % dash if dash else ""
        m = ' marker-end="url(#arrow)"' if marker else ""
        self.add('<line x1="%g" y1="%g" x2="%g" y2="%g" stroke="%s" '
                 'stroke-width="%g" stroke-linecap="round"%s%s/>'
                 % (x1, y1, x2, y2, stroke or self.c["muted"], width, d, m))

    def path(self, d, stroke=None, width=1.5, marker=True, dash=None):
        m = ' marker-end="url(#arrow)"' if marker else ""
        da = ' stroke-dasharray="%s"' % dash if dash else ""
        self.add('<path d="%s" fill="none" stroke="%s" stroke-width="%g" '
                 'stroke-linecap="round" stroke-linejoin="round"%s%s/>'
                 % (d, stroke or self.c["muted"], width, m, da))

    def render(self, title):
        c = self.c
        head = [
            '<svg xmlns="http://www.w3.org/2000/svg" width="%g" height="%g" '
            'viewBox="0 0 %g %g" role="img" aria-label="%s">'
            % (self.w, self.h, self.w, self.h, esc(title)),
            '  <title>%s</title>' % esc(title),
            '  <defs>',
            '    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
            'markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
            '      <path d="M 0 1 L 9 5 L 0 9 z" fill="%s"/>' % c["muted"],
            '    </marker>',
            '    <marker id="arrow-accent" viewBox="0 0 10 10" refX="9" '
            'refY="5" markerWidth="6" markerHeight="6" '
            'orient="auto-start-reverse">',
            '      <path d="M 0 1 L 9 5 L 0 9 z" fill="%s"/>' % c["accent"],
            '    </marker>',
            '  </defs>',
            '  <rect width="%g" height="%g" fill="%s"/>' % (self.w, self.h,
                                                            c["bg"]),
        ]
        return "\n".join(head + self.parts + ["</svg>", ""])


def panel(cv, x, y, w, h, label, kicker=None):
    """A titled box: kicker above it, rounded panel, label inside the header."""
    c = cv.c
    if kicker:
        cv.text(x, y - 14, kicker.upper(), size=10.5, fill=c["muted"],
                weight="600", spacing=1.4)
    cv.rect(x, y, w, h, fill=c["panel"], stroke=c["border"])
    cv.rect(x, y, w, 30, fill=c["panel2"], stroke="none", r=10)
    cv.rect(x, y + 20, w, 10, fill=c["panel2"], stroke="none", r=0)
    cv.line(x, y + 30, x + w, y + 30, stroke=c["border"], width=1, marker=False)
    cv.text(x + 14, y + 20, label, size=12.5, weight="600")


# ------------------------------------------------------------------ figure one

def architecture(theme):
    """Three columns and one route around the middle one."""
    c = THEMES[theme]
    cv = Canvas(940, 446, c)

    ax, ay, aw, ah = 30, 66, 220, 118
    gx, gy, gw, gh = 330, 66, 250, 176
    vx, vy, vw, vh = 660, 66, 250, 150
    kx, ky, kw, kh = 660, 306, 250, 96

    # --- the agent
    panel(cv, ax, ay, aw, ah, "the agent", "asks")
    for i, row in enumerate(("Read   Grep   Glob", "Edit   Write   Bash")):
        cv.text(ax + 16, ay + 58 + i * 22, row, size=12, family=MONO,
                fill=c["text"])
    cv.text(ax + 16, ay + ah - 14, "approving its own tool calls", size=10.5,
            fill=c["muted"])

    # --- the guard
    panel(cv, gx, gy, gw, gh, "PreToolUse guard", "refuses")
    rows = (".env   ~/.ssh   *.pem", "~/.netrc   ~/.aws/credentials",
            "~/Library/Keychains", "vlt get / show / export / rm",
            "searching the disk for keys")
    for i, row in enumerate(rows):
        cv.text(gx + 16, gy + 56 + i * 21, row, size=11.5, family=MONO,
                fill=c["text"])
    cv.text(gx + 16, gy + gh - 12, "decided before the tool runs", size=10.5,
            fill=c["muted"])

    # --- the vault
    panel(cv, vx, vy, vw, vh, "the vault", "holds")
    vrows = (("store/", "one AES-256-GCM file per record"),
             ("index.json", "names and field names only"),
             ("audit.log", "who read what, and when"))
    for i, (name, desc) in enumerate(vrows):
        cv.text(vx + 16, vy + 58 + i * 32, name, size=11.5, family=MONO,
                fill=c["accent"])
        cv.text(vx + 16, vy + 72 + i * 32, desc, size=10.5, fill=c["muted"])

    # --- the keyring
    panel(cv, kx, ky, kw, kh, "OS keyring", "unlocks")
    cv.text(kx + 16, ky + 56, "Secret Service  ·  macOS keychain", size=11.5,
            family=MONO, fill=c["text"])
    cv.text(kx + 16, ky + 76, "the master key, never a file on disk",
            size=10.5, fill=c["muted"])

    # --- the refused route
    cv.line(ax + aw, ay + 62, gx - 8, ay + 62)
    cv.text((ax + aw + gx) / 2, ay + 52, "tool call", size=11, fill=c["muted"],
            anchor="middle")
    cv.path("M %g %g L %g %g" % (gx + gw / 2, gy + gh, gx + gw / 2, gy + gh + 34),
            stroke=c["danger"])
    cv.text(gx + gw / 2, gy + gh + 56, "denied, and logged", size=11.5,
            fill=c["danger"], anchor="middle", weight="600")

    # --- the permitted route: around the guard, into the vault from the left
    y0 = 366
    turn = vx - 46
    cv.path("M %g %g L %g %g L %g %g L %g %g L %g %g"
            % (ax + 44, ay + ah, ax + 44, y0, turn, y0,
               turn, vy + vh - 34, vx - 5, vy + vh - 34),
            stroke=c["accent"])
    cv.text(ax + 60, y0 - 44, "vlt list · peek · exec", size=11.5, family=MONO,
            fill=c["accent"])
    cv.text(ax + 60, y0 - 26, "vlt file · render · request", size=11.5,
            family=MONO, fill=c["accent"])
    cv.text(ax + 60, y0 + 24, "structure out, values through, never printed",
            size=11, fill=c["muted"])

    # --- vault -> keyring
    cv.line(vx + vw - 44, vy + vh, vx + vw - 44, ky - 6)
    cv.text(vx + vw - 34, (vy + vh + ky) / 2 + 4, "master key", size=11,
            fill=c["muted"])

    return cv.render("credfence architecture")


# ------------------------------------------------------------------ figure two

def protocol(theme):
    """Four cards, left to right, and where the value actually crosses."""
    c = THEMES[theme]
    cv = Canvas(940, 218, c)

    steps = [
        ("1", "vlt list", "what exists",
         ["no decryption at all —", "names and field names only"]),
        ("2", "vlt peek", "what shape it is",
         ["ghp_••••  [40 chars, base64url]",
          "enough to check, never to use"]),
        ("3", "vlt exec", "use it without seeing it",
         ["into a child process, a file,", "or a rendered config"]),
        ("4", "vlt request", "when it is missing",
         ["opens a separate window", "for the person to type it in"]),
    ]

    x, y, w, h, gap = 24, 24, 213, 132, 15
    for i, (n, cmd, title, lines) in enumerate(steps):
        bx = x + i * (w + gap)
        cv.rect(bx, y, w, h, fill=c["panel"], stroke=c["border"])
        cv.rect(bx + 16, y + 16, 24, 22, fill=c["accent"], stroke="none", r=6)
        cv.text(bx + 28, y + 32, n, size=12, fill=c["bg"], weight="700",
                anchor="middle")
        cv.text(bx + 50, y + 32, cmd, size=13, family=MONO, weight="600",
                fill=c["accent"])
        cv.text(bx + 16, y + 66, title, size=12.5, weight="600")
        for j, ln in enumerate(lines):
            cv.text(bx + 16, y + 92 + j * 18, ln, size=10.5, fill=c["muted"])
        if i < len(steps) - 1:
            cv.line(bx + w + 2, y + h / 2, bx + w + gap - 4, y + h / 2,
                    stroke=c["border"], width=1.5)

    bar = y + h + 22
    cv.rect(x, bar, 4 * w + 3 * gap, 36, fill=c["panel2"], stroke=c["border"],
            r=8)
    cv.rect(x, bar, 4, 36, fill=c["accent"], stroke="none", r=2)
    cv.text(x + 18, bar + 23,
            "The value crosses only at step 3, into a process the agent "
            "cannot read back — never into the transcript.",
            size=11.5, fill=c["text"])

    return cv.render("the protocol an agent follows")


FIGURES = {"architecture": architecture, "protocol": protocol}


def main():
    check = "--check" in sys.argv
    os.makedirs(OUT, exist_ok=True)
    stale = []
    for name, fn in sorted(FIGURES.items()):
        for theme in ("light", "dark"):
            path = os.path.join(OUT, "%s-%s.svg" % (name, theme))
            svg = fn(theme)
            if check:
                old = open(path).read() if os.path.exists(path) else None
                if old != svg:
                    stale.append(os.path.relpath(path, os.path.dirname(HERE)))
                continue
            with open(path, "w") as fh:
                fh.write(svg)
            print("  wrote %s (%d bytes)" % (os.path.relpath(path), len(svg)))
    if check:
        if stale:
            print("out of date, re-run without --check:")
            for p in stale:
                print("  " + p)
            return 1
        print("figures are up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
