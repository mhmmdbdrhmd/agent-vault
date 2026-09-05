"""Shared test harness: an isolated vault, never the caller's real one.

Every suite imports this first. It builds a throwaway VLT_HOME in a temp
directory, so a test can create, reveal and destroy records without touching
anything real. This is not tidiness — an earlier version of these tests ran
against the developer's live vault, and a test that unmasked a field printed a
production credential into the log.

Set VLT_TEST_KEEP=1 to leave the temp vault behind for inspection.
"""

import atexit
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VLT = os.path.join(REPO, "vlt")
HOOK = os.path.join(REPO, "integrations", "claude-code", "vault-guard.py")

# A throwaway vault for this process only.
VLT_HOME = tempfile.mkdtemp(prefix="vlt-test-")

# Redirect THIS process too, not just the subprocesses it launches. A suite that
# imports vltlib directly reads VLT_HOME at import time, so without this it
# operates on the caller's real vault — which is how a test once left records
# behind in a production store. Must happen before any `import vltlib`.
os.environ["VLT_HOME"] = VLT_HOME
os.environ["VLT_ALLOW_FILE_KEY"] = "1"
# Never touch the real login keyring: a temp vault would leave an
# entry behind on every run.
os.environ["VLT_NO_KEYRING"] = "1"
os.environ.pop("DISPLAY", None)
os.environ.pop("WAYLAND_DISPLAY", None)

# ---------------------------------------------------------------- a fake HOME
# The guard is asked about ~/.ssh, ~/.netrc and friends. Answering from the
# real home makes every such assertion depend on what the person running the
# tests happens to own — which is exactly how a hole in the bash guard reached
# CI reported as a pass. Build the filesystem the tests describe instead.
# Kept so the one suite that must reach the real system keyring can put it
# back. Everything else wants the fixture.
REAL_HOME = os.path.expanduser("~")
FAKE_HOME = os.path.join(VLT_HOME, "home")
# The CONTENT is never read by any assertion — only the paths matter. So it is
# deliberately not key-shaped: a PEM header here, however fake, makes every
# secret scanner in the pipeline report this repository as leaking a private
# key, and a scanner whose findings are all known-and-ignored is a scanner
# nobody reads.
_TREE = {
    ".ssh/id_rsa": "fixture: a file at this path, not key material\n",
    ".ssh/id_ed25519": "fixture: a file at this path, not key material\n",
    ".ssh/id_rsa.pub": "ssh-rsa AAAAB3NzaC1yc2E example\n",
    ".ssh/config": "Host example\n  User exampleuser\n",
    ".ssh/known_hosts": "example.invalid ssh-ed25519 AAAAC3Nz\n",
    ".netrc": "machine example.invalid login exampleuser password EXAMPLE\n",
    ".aws/credentials": "[default]\naws_access_key_id = EXAMPLE\n",
    ".npmrc": "//registry.npmjs.org/:_authToken=EXAMPLE\n",
    "projects/webapp/.env": "API_KEY=EXAMPLE\n",
    "projects/webapp/app.py": "print('hello')\n",
}
for _rel, _body in _TREE.items():
    _p = os.path.join(FAKE_HOME, _rel)
    os.makedirs(os.path.dirname(_p), exist_ok=True)
    with open(_p, "w") as _fh:
        _fh.write(_body)
os.environ["HOME"] = FAKE_HOME

_BASE = dict(os.environ)
_BASE.update({
    "VLT_HOME": VLT_HOME,
    "HOME": FAKE_HOME,
    # No Secret Service in CI: the file key is the deliberate test choice.
    "VLT_ALLOW_FILE_KEY": "1",
    "VLT_NO_KEYRING": "1",
    "PYTHONPATH": REPO + os.pathsep + _BASE_PYTHONPATH
    if (_BASE_PYTHONPATH := os.environ.get("PYTHONPATH", "")) else REPO,
})
_BASE.pop("VLT_HUMAN", None)
_BASE.pop("VLT_TEST_CONFIRM", None)

# No desktop, ever. The human-confirmation gate falls back to a zenity dialog
# when it cannot find a terminal; with DISPLAY set, a test run interrupts the
# person at the keyboard with prompts they did not ask for and cannot judge.
# A real background agent has no desktop either, so removing it is also the
# honest simulation.
_BASE.pop("DISPLAY", None)
_BASE.pop("WAYLAND_DISPLAY", None)

# A person at a terminal. VLT_TEST_CONFIRM stands in for the TTY that a real
# person would have; it is the only thing that may skip the confirmation.
HUMAN = dict(_BASE, VLT_HUMAN="1", VLT_TEST_CONFIRM="1")
# An agent: no VLT_HUMAN, no confirmation escape, no desktop.
AGENT = dict(_BASE, CLAUDECODE="1")

sys.path.insert(0, REPO)


def _cleanup():
    if os.environ.get("VLT_TEST_KEEP") == "1":
        sys.stderr.write("test vault kept at %s\n" % VLT_HOME)
        return
    shutil.rmtree(VLT_HOME, ignore_errors=True)


atexit.register(_cleanup)


def vlt(args, env=None, text=True):
    """Run the repo's vlt against the throwaway vault."""
    return subprocess.run([sys.executable, VLT] + list(args),
                          capture_output=True, text=text,
                          env=env if env is not None else HUMAN)


def init_vault():
    r = vlt(["init"])
    if r.returncode != 0:
        raise SystemExit("could not initialise the test vault:\n%s" % r.stderr)
    return VLT_HOME


# Initialise on import. Suites that use vltlib directly never get the chance to
# call this first — the library reads its key the moment they touch a record —
# and an uninitialised vault fails in a way that looks like a code bug.
init_vault()


# A standard record for suites that need something to look at. Values are
# obviously synthetic so that a failing test printing one is embarrassing
# rather than dangerous.
FIXTURE = "test/dummy"
FIXTURE_TOKEN = "EXAMPLEtokenAAAABBBBCCCCDDDDEEEEFFFF0123"   # 40 chars
FIXTURE_USER = "exampleuser"


def make_fixture(name=FIXTURE):
    """Create the standard fixture record and return its name."""
    vlt(["set", name, "token", FIXTURE_TOKEN, "--env", "GITHUB_TOKEN"])
    vlt(["set", name, "username", FIXTURE_USER, "--env", "GITHUB_USER"])
    return name


class Report:
    """Collects pass/fail so every suite prints the same way."""

    def __init__(self, title=""):
        self.fails = []
        if title:
            print(title)

    def check(self, label, ok, detail=""):
        print("%-5s %s%s" % ("ok " if ok else "FAIL", label,
                             "" if ok else "   " + str(detail)[:140]))
        if not ok:
            self.fails.append(label)
        return ok

    def done(self):
        print()
        if self.fails:
            print("%d FAILURE(S): %s" % (len(self.fails), ", ".join(self.fails)))
        else:
            print("all clear")
        return 1 if self.fails else 0
