"""`vlt scan` — the inventory report.

This suite exists because the command shipped broken. Six module constants it
referenced were never defined, so it raised `NameError` on the first directory
it walked, and nothing noticed: no suite invoked it, and there was no linter.
It was listed in the README as agent-safe the whole time.

What is pinned here is what the command promises:

  * it runs, and finds credential-shaped files by name;
  * it separates what should move into the vault from what the machine needs
    left where it is;
  * it reports field NAMES and never field VALUES — the earlier version of the
    name extractor matched base64 inside a PEM body and printed slices of the
    key itself under "keys:";
  * it changes nothing on disk.
"""

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

R = TH.Report()

# Values that must never appear in the report. Fake, but shaped like the real
# thing so that a leak would be a real leak.
SECRET_ENV = "EXAMPLEsecretVALUE0123456789abcdef"
SECRET_KEY_BODY = "\n".join(["QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlq"] * 6)

tree = tempfile.mkdtemp(prefix="vlt-scan-")
home = os.path.join(tree, "home")
proj = os.path.join(home, "work", "app")
ssh = os.path.join(home, ".ssh")
for d in (proj, ssh):
    os.makedirs(d)

with open(os.path.join(proj, ".env"), "w") as fh:
    fh.write("API_KEY=%s\nDB_HOST=db.example.invalid\n# password: not a field\n"
             % SECRET_ENV)
with open(os.path.join(ssh, "id_ed25519"), "w") as fh:
    fh.write("-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n"
             "-----END OPENSSH PRIVATE KEY-----\n" % SECRET_KEY_BODY)
with open(os.path.join(proj, ".env.example"), "w") as fh:
    fh.write("API_KEY=\nDB_HOST=\n")
with open(os.path.join(proj, "notes.md"), "w") as fh:
    fh.write("The password is stored in the vault now.\n")

# A cache directory: anything in here belongs to a package, not to the user.
cache = os.path.join(home, ".cache", "pip", "http")
os.makedirs(cache)
with open(os.path.join(cache, "credentials"), "w") as fh:
    fh.write("user=someone-elses-fixture\n")


def scan(*extra):
    r = subprocess.run([sys.executable, TH.VLT, "scan", home, "--depth", "6"]
                       + list(extra), capture_output=True, text=True,
                       env=TH.AGENT)
    return r


r = scan()
R.check("scan runs at all", r.returncode == 0,
        (r.stderr or r.stdout).strip().split("\n")[-1][:140])

out = r.stdout
R.check("finds a .env", "/.env" in out and ".env.example" not in out,
        "an .env.example is a template, not a credential")
R.check("finds an ssh private key", "id_ed25519" in out, "")
R.check("leaves the ssh key in place rather than proposing migration",
        "LEAVE IN PLACE" in out
        and out.index("id_ed25519") > out.index("LEAVE IN PLACE"),
        "ssh keys are machine-operational: openssh needs the file")
R.check("skips package caches", "someone-elses-fixture" not in out
        and "/.cache/" not in out, "a hit inside a cache is not your secret")

R.check("reports the field NAME", "API_KEY" in out, "")
R.check("never prints the field VALUE", SECRET_ENV not in out,
        "a scan that prints values is worse than no scan")
R.check("never prints key material", "QUJDREVG" not in out, "")
R.check("does not mistake a comment for a field", "password" not in out.lower()
        or "API_KEY" in out, "")

R.check("says plainly that nothing changed",
        "NOTHING has been changed" in out or "nothing has been changed" in out,
        "")

# --json is what an agent would parse; it must carry the same guarantee.
rj = scan("--json")
R.check("--json is valid json", rj.returncode == 0, rj.stderr.strip()[:120])
try:
    data = json.loads(rj.stdout)
except Exception as exc:
    data = []
    R.check("--json parses", False, str(exc)[:120])
else:
    R.check("--json parses", True, "")
R.check("--json leaks no value", SECRET_ENV not in rj.stdout
        and "QUJDREVG" not in rj.stdout, "")

names = {os.path.basename(h["path"]) for h in data} if data else set()
R.check("--json lists the same files", {".env", "id_ed25519"} <= names,
        "got %r" % sorted(names))
R.check("--json marks the ssh key machine-operational",
        any(h["machine_operational"] for h in data
            if os.path.basename(h["path"]) == "id_ed25519"), "")

# Nothing on disk moved.
still_there = all(os.path.exists(p) for p in
                  (os.path.join(proj, ".env"), os.path.join(ssh, "id_ed25519")))
R.check("scan is read-only", still_there, "a file the scan named is gone")

# --deep looks at content, which is where the PEM-body bug lived.
with open(os.path.join(proj, "config.json"), "w") as fh:
    fh.write('{"api_key": "%s"}\n' % SECRET_ENV)
rd = scan("--deep")
R.check("--deep finds a secret-shaped assignment", "config.json" in rd.stdout,
        "")
R.check("--deep still prints no value", SECRET_ENV not in rd.stdout, "")

import shutil                                            # noqa: E402
shutil.rmtree(tree, ignore_errors=True)
sys.exit(R.done())
