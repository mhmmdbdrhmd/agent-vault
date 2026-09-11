"""A real OpenSSH key, stored and written back, validated by OpenSSH itself.

The rest of the multi-line work is checked against fixtures this repository
wrote, which only proves the code agrees with itself. This suite generates a
throwaway key with `ssh-keygen`, puts it through the vault, writes it out with
`vlt file`, and asks `ssh-keygen -y` to derive the public key from it. That
last step is the claim that actually matters: OpenSSH rejects a key whose final
`-----END …-----` has no newline after it, and reports it as "invalid format"
rather than as one missing byte — so a vault that drops that byte hands you a
key file that looks right and does not work.

The key never leaves the temp directory and is never printed.
"""

import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                       # noqa: E402

sys.path.insert(0, TH.REPO)
import vltlib as V                                         # noqa: E402

if not shutil.which("ssh-keygen"):
    print("SKIP: ssh-keygen is not installed")
    sys.exit(0)

fails = []


def check(label, ok, detail=""):
    print("%-5s %s%s" % ("ok " if ok else "FAIL", label,
                         "" if ok else "   " + str(detail)[:200]))
    if not ok:
        fails.append(label)


TH.init_vault()
work = os.path.join(TH.VLT_HOME, "sshkey")
os.makedirs(work, mode=0o700, exist_ok=True)
src = os.path.join(work, "generated")

r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "credfence-test", "-f", src],
                   capture_output=True, text=True)
if r.returncode != 0 or not os.path.exists(src):
    print("SKIP: ssh-keygen could not generate a key here (%s)"
          % (r.stderr or "").strip()[:120])
    sys.exit(0)

with open(src) as fh:
    original = fh.read()
with open(src + ".pub") as fh:
    want_pub = fh.read().split()[1]          # the base64 blob, not the comment

check("the generated key is armoured", V.is_armoured(original))

# ------------------------------------------------------------ into the vault
r = subprocess.run([sys.executable, TH.VLT, "set", "ssh/roundtrip", "key", "-"],
                   input=original, capture_output=True, text=True, env=TH.HUMAN)
check("`vlt set … -` accepted the key", r.returncode == 0, r.stderr)

rec = V.load("ssh/roundtrip") if V.exists("ssh/roundtrip") else {"fields": {}}
stored = rec["fields"].get("key") or ""
check("the stored key is byte-identical to the generated one",
      stored == original,
      "stored %d chars, generated %d" % (len(stored), len(original)))

# ---------------------------------------------------------- back out to a file
out = os.path.join(work, "restored")
r = subprocess.run([sys.executable, TH.VLT, "file", "ssh/roundtrip", "key",
                    "--out", out, "--mode", "0600"],
                   capture_output=True, text=True, env=TH.HUMAN)
check("`vlt file` wrote it", r.returncode == 0 and os.path.exists(out), r.stderr)
check("the written file is 0600 — ssh refuses anything looser",
      os.path.exists(out) and (os.stat(out).st_mode & 0o777) == 0o600)

with open(out) as fh:
    restored = fh.read()
check("the written file matches the original byte for byte",
      restored == original)

# ------------------------------------------------- the verdict that is not ours
r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", out],
                   capture_output=True, text=True)
check("OpenSSH accepts the key the vault wrote",
      r.returncode == 0, (r.stderr or r.stdout).strip()[:160])
check("and derives the same public key it started from",
      r.returncode == 0 and want_pub in r.stdout,
      "derived %r" % (r.stdout.split()[1][:24] if r.returncode == 0 else None))

# ------------------------------------------- and the byte, shown to be load-bearing
# Not a hypothetical: this is the file the old code produced.
truncated = os.path.join(work, "unterminated")
fd = os.open(truncated, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as fh:
    fh.write(original.rstrip("\n"))
r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", truncated],
                   capture_output=True, text=True)
check("OpenSSH rejects the same key without its trailing newline",
      r.returncode != 0,
      "it was accepted, so this newline is not what makes the difference")

print()
print("all clear" if not fails else "%d FAILURE(S): %s" % (len(fails), fails))
sys.exit(1 if fails else 0)
