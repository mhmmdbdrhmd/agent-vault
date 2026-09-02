#!/usr/bin/env python3
"""Run every suite against an isolated vault. Exit non-zero if any fails.

    python3 tests/run_all.py            # everything
    python3 tests/run_all.py --fast     # skip the pty UI tests
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# (name, needs a pseudo-terminal, seconds)
SUITES = [
    ("evasion_test", False, 90),   # adversarial bypasses of the bash guard
    ("hooktest",     False, 90),   # allow/deny, including false positives
    ("regress",      False, 60),   # compound commands
    ("prose_test",   False, 90),   # English is not a filesystem path
    ("exec_test",    False, 90),   # no `vlt exec` path prints a secret
    ("bypass_test",  False, 60),   # VLT_HUMAN=1 inside a script is refused
    ("hide_test",    False, 90),   # per-record masking
    ("masking_test", False, 90),   # unknown fields are masked, not printed
    ("rename_test",  False, 90),   # rename re-encrypts and cleans up
    ("edit_test",    False, 90),   # editing semantics
    ("form_test",    False, 30),   # type defaults, Save/Cancel
    ("layout_test",  False, 30),   # form geometry
    ("ui_test",      True, 180),   # the UI, driven through a pty
]


def main():
    fast = "--fast" in sys.argv
    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    failed, skipped = [], []

    for name, needs_pty, timeout in SUITES:
        if only and name not in only:
            continue
        if fast and needs_pty:
            skipped.append(name)
            continue
        path = os.path.join(HERE, name + ".py")
        if not os.path.exists(path):
            failed.append((name, "missing"))
            continue
        started = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            print("  %-14s TIMEOUT after %ss" % (name, timeout))
            failed.append((name, "timeout"))
            continue
        took = time.time() - started
        if r.returncode == 0:
            print("  %-14s pass   (%.1fs)" % (name, took))
        else:
            print("  %-14s FAIL   (%.1fs)" % (name, took))
            for line in (r.stdout + r.stderr).splitlines():
                if line.startswith("FAIL") or "Error" in line or "error" in line:
                    print("      %s" % line[:160])
            failed.append((name, "failed"))

    print()
    if skipped:
        print("skipped (--fast): %s" % ", ".join(skipped))
    if failed:
        print("%d SUITE(S) FAILED: %s"
              % (len(failed), ", ".join(n for n, _ in failed)))
        return 1
    print("all suites passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
