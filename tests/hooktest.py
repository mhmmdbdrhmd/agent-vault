
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

import importlib.util as _ilu

_spec = _ilu.spec_from_file_location("vault_guard", TH.HOOK)
_guard = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_guard)
SELF_HOOK, SELF_CLI = _guard.SELF_PATHS[0], _guard.SELF_PATHS[1]
STORE_FILE = os.path.join(TH.VLT_HOME, "store", "test", "dummy.vlt")
MASTER_KEY = os.path.join(TH.VLT_HOME, ".master.key")

sys.path.insert(0, TH.REPO)
import json, subprocess, sys, os, tempfile

H = os.path.expanduser("~")

# --- self-setup: the "rendered" cases need files vlt actually wrote ----------
# Deliberately given names the guard would otherwise allow, so these cases test
# the rendered-file registry rather than the filename patterns.
_TMP = tempfile.mkdtemp(prefix="vlt-hooktest-")
_TOK = os.path.join(_TMP, "keymaterial.out")
_ENV = os.path.join(_TMP, "rendered.conf")
TH.make_fixture()
_HAVE_FIXTURE = (
    TH.vlt(["file", TH.FIXTURE, "token", "--out", _TOK]).returncode == 0
    and TH.vlt(["render", "--secret", TH.FIXTURE, "--out", _ENV]).returncode == 0)
HOOK = TH.HOOK
CASES = [
 ("Read", {"file_path": H + "/.ssh/id_rsa"}, "DENY"),
 ("Read", {"file_path": H + "/.ssh/id_rsa.pub"}, "ALLOW"),
 ("Read", {"file_path": H + "/.netrc"}, "DENY"),
 ("Read", {"file_path": H + "/projects/webapp/.env"}, "DENY"),
 ("Read", {"file_path": H + "/projects/webapp/.env.example"}, "ALLOW"),
 ("Read", {"file_path": H + "/x/.env.local"}, "DENY"),
 ("Read", {"file_path": H + "/x/.env.production"}, "DENY"),
 ("Read", {"file_path": STORE_FILE}, "DENY"),
 ("Read", {"file_path": MASTER_KEY}, "DENY"),
 ("Read", {"file_path": H + "/.claude/.credentials.json"}, "DENY"),
 ("Read", {"file_path": _ENV}, "DENY" if _HAVE_FIXTURE else "ALLOW"),
 ("Read", {"file_path": _TOK}, "DENY" if _HAVE_FIXTURE else "ALLOW"),
 ("Read", {"file_path": H + "/projects/webapp/README.md"}, "ALLOW"),
 ("Edit", {"file_path": SELF_HOOK}, "DENY"),
 ("Edit", {"file_path": SELF_CLI}, "DENY"),
 ("Edit", {"file_path": H + "/projects/webapp/app.py"}, "ALLOW"),
 ("Bash", {"command": "cat ~/.ssh/id_ed25519"}, "DENY"),
 ("Bash", {"command": "cat " + H + "/projects/webapp/credentials"}, "DENY"),
 ("Bash", {"command": "vlt get github.com/biss token"}, "DENY"),
 ("Bash", {"command": "vlt show test/dummy"}, "DENY"),
 ("Bash", {"command": "secret-tool lookup application vlt"}, "DENY"),
 ("Bash", {"command": "python3 -c 'import secretstorage'"}, "DENY"),
 ("Bash", {"command": "grep -r 'BEGIN RSA PRIVATE KEY' " + H}, "DENY"),
 ("Bash", {"command": "grep -rn 'ghp_' ~/github"}, "DENY"),
 ("Bash", {"command": "grep -rn \"api_key = 'abcdef123'\" ."}, "DENY"),
 ("Bash", {"command": "find " + H + "/.ssh -name 'id_*'"}, "DENY"),
 ("Bash", {"command": "cat " + _ENV}, "DENY" if _HAVE_FIXTURE else "ALLOW"),
 ("Bash", {"command": "vlt list"}, "ALLOW"),
 ("Bash", {"command": "vlt peek test/dummy"}, "ALLOW"),
 ("Bash", {"command": "vlt exec test/dummy -- gh auth status"}, "ALLOW"),
 ("Bash", {"command": "vlt request stripe.com/biss --fields key"}, "ALLOW"),
 ("Bash", {"command": "ls -la " + H + "/projects"}, "ALLOW"),
 ("Bash", {"command": "grep -rn 'password' ~/github/mywebsite"}, "ALLOW"),
 ("Grep", {"pattern": "ghp_[A-Za-z0-9]+", "path": H}, "DENY"),
 ("Grep", {"pattern": "TODO", "path": H + "/projects/webapp"}, "ALLOW"),
 ("Grep", {"pattern": "handlePassword", "path": H + "/projects/webapp"}, "ALLOW"),
 ("Glob", {"pattern": "**/.env*"}, "DENY"),
 ("Glob", {"pattern": "**/*.pem"}, "DENY"),
 ("Glob", {"pattern": "**/*.py"}, "ALLOW"),
]
fails = 0
for tool, inp, want in CASES:
    ev = json.dumps({"tool_name": tool, "tool_input": inp})
    r = subprocess.run([sys.executable, HOOK], input=ev,
                   capture_output=True, text=True, env=TH.AGENT)
    got = "DENY" if '"deny"' in r.stdout else "ALLOW"
    ok = got == want
    fails += not ok
    label = str(inp.get("file_path") or inp.get("command") or inp.get("pattern"))[:64]
    print("%-5s %-6s %-6s %-7s %s" % ("ok " if ok else "FAIL", tool, want, got, label))
import shutil
shutil.rmtree(_TMP, ignore_errors=True)
print("\n%d/%d passed" % (len(CASES)-fails, len(CASES)))
sys.exit(1 if fails else 0)
