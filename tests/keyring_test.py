"""The keyring backends, round-tripped against the real system keyring.

There are two: the macOS login keychain via `/usr/bin/security`, and the Secret
Service via D-Bus on Linux. They are the only place the master key is supposed
to live, so "it compiles" is not evidence that either works.

This suite writes a key under a label scoped to a throwaway `VLT_HOME`, reads it
back, finds it in the listing, and deletes it. It is **skipped unless
`VLT_KEYRING_TEST=1`** because it touches the machine's real keyring, and a test
run should not leave entries in — or pop dialogs at — someone's desktop session.
CI sets the flag; a laptop does not.

The macOS half is what makes the platform claim in the README checkable: it runs
on a `macos-latest` runner in CI, not on the author's machine.
"""

import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)

R = TH.Report()

if os.environ.get("VLT_KEYRING_TEST") != "1":
    print("skipped: set VLT_KEYRING_TEST=1 to exercise the real system keyring")
    print("         (it writes and deletes one entry under a temp VLT_HOME)")
    raise SystemExit(0)

# harness.py disables the keyring for every other suite. This one needs it, and
# it needs vltlib re-read with the temp VLT_HOME already in place so the label
# is scoped away from the user's own vault.
os.environ.pop("VLT_NO_KEYRING", None)
import vltlib as V                                      # noqa: E402

backend = V.keyring_backend()
R.check("a backend is selected", backend in ("macos", "secretservice"),
        "got %r" % backend)
R.check("the label is scoped to this VLT_HOME",
        V.KEYRING_LABEL != "vlt-master-identity",
        "label %r would collide with a real vault" % V.KEYRING_LABEL)

key = secrets.token_bytes(32)
wrote = False
try:
    V._keyring_set(key)
    wrote = True
    R.check("write succeeds", True, "")

    got = V._keyring_get()
    R.check("read returns the same 32 bytes", got == key,
            "got %r bytes" % (len(got) if got else None))

    labels = [lbl for lbl, _ in V.keyring_items()]
    R.check("the entry appears in the listing", V.KEYRING_LABEL in labels,
            "listing: %r" % (labels[:5],))

    # Overwriting must replace, not accumulate: two master keys for one vault
    # means a coin flip over whether the store still decrypts.
    key2 = secrets.token_bytes(32)
    V._keyring_set(key2)
    R.check("overwrite replaces the value", V._keyring_get() == key2, "")
    R.check("overwrite leaves exactly one entry",
            [lbl for lbl, _ in V.keyring_items()].count(V.KEYRING_LABEL) == 1,
            "duplicates would make decryption a coin flip")

    R.check("delete removes it",
            V.keyring_delete(V.KEYRING_LABEL, V._KEYRING_PURPOSE) is not False
            and V._keyring_get() is None, "")
    wrote = False
finally:
    if wrote:
        try:
            V.keyring_delete(V.KEYRING_LABEL, V._KEYRING_PURPOSE)
        except Exception as exc:
            print("  WARNING: could not clean up %s: %s" % (V.KEYRING_LABEL, exc))

sys.exit(R.done())
