"""The guard must not fire on English, and must not assert facts it never checked.

Every ALLOW case here is taken from a real false denial: a session configuring a
VPN was blocked because the word "credentials" appeared in a comment inside a
heredoc bound for a remote host. The denial named a path that did not exist,
phrased as an established fact, and the user reasonably concluded the agent had
gone after their real credentials file.

The DENY cases exist because the obvious fix — "only match tokens containing a
slash" — would reopen `cd ~/.ssh && cat id_rsa`. Existence is what separates an
operation from prose, so both halves are pinned here.
"""

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as TH                                    # noqa: E402

sys.path.insert(0, TH.REPO)

R = TH.Report()
HOME = os.path.expanduser("~")


def ask(cmd):
    ev = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
    r = subprocess.run([sys.executable, TH.HOOK], input=ev,
                       capture_output=True, text=True, env=TH.AGENT)
    if '"deny"' not in r.stdout:
        return "ALLOW", ""
    try:
        reason = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
    except Exception:
        reason = r.stdout
    return "DENY", reason


# ---------------------------------------------------------------- prose cases
# The exact shape that was denied in the field.
REMOTE_SCRIPT = (
    "ssh -p 2023 root@192.0.2.1 '"
    "cat <<EOF > /etc/config/openvpn\n"
    "# LuCI-managed profile = tested profile + credentials and hooks baked in\n"
    "option enabled 1\n"
    "EOF\n"
    "uci commit openvpn'"
)

PROSE = [
    ("bare word in a heredoc comment", REMOTE_SCRIPT),
    ("bare word in a plain comment", "uci set foo=bar   # credentials go here"),
    ("bare word as prose in echo", "echo 'rotate the credentials next week'"),
    ("word inside a longer sentence",
     "git commit -m 'store credentials in the vault, not in .env files'"),
    ("secret as an English word", "echo 'the secret is there is no secret'"),
    ("benign command beside prose", "vlt audit --tail 20"),
]
for label, cmd in PROSE:
    got, why = ask(cmd)
    R.check("prose allowed: %s" % label, got == "ALLOW", why.split("\n")[0])

# ------------------------------------------------------- real operations still die
tmp = tempfile.mkdtemp(prefix="vlt-prose-")
real_cred = os.path.join(tmp, "credentials")
with open(real_cred, "w") as fh:
    fh.write("user=example\npassword=EXAMPLE-not-real\n")

OPERATIONS = [
    ("absolute path to a credential file", "cat " + real_cred),
    ("bare name that resolves to a real file",
     "cd " + tmp + " && cat credentials"),
    ("ssh key by absolute path", "cat " + HOME + "/.ssh/id_" + "rsa"),
    ("cd then bare ssh key", "cd " + HOME + "/.ssh && cat id_" + "rsa"),
    ("dotfile pattern even if absent", "cat " + tmp + "/nothing-here/.env"),
    ("explicit relative path", "cat ./.netrc"),
]
for label, cmd in OPERATIONS:
    got, why = ask(cmd)
    R.check("still blocked: %s" % label, got == "DENY", why.split("\n")[0])

# ------------------------------------------------------------- message honesty
got, why = ask("cat " + tmp + "/nothing-here/.env")
R.check("unverified match does not assert existence",
        got == "DENY" and "is a credential file" not in why.split("\n")[0],
        why.split("\n")[0])
R.check("unverified match names the token that matched",
        "token" in why and "not checked for existence" in why,
        why.split("\n")[0])

got, why = ask("cat " + real_cred)
R.check("verified match may state it plainly",
        got == "DENY" and "is a credential file" in why, why.split("\n")[0])
R.check("denial says which part of the command tripped it",
        "in:" in why or real_cred in why, why.split("\n")[0])

# ------------------------------------------------- heredoc body is data, not ops
got, why = ask("cat <<'EOF' > /tmp/x.conf\ncat ~/.ssh/id_" + "rsa\nEOF")
R.check("heredoc body is not treated as an operation", got == "ALLOW",
        why.split("\n")[0])

got, why = ask("cat <<'EOF' | sh\necho hi\nEOF")
R.check("heredoc piped to a shell is still refused", got == "DENY",
        why.split("\n")[0])

# The opener line stays visible, so a redirect target on it is still checked.
# (`authorized_keys` is deliberately NOT covered: it holds public keys. Writing
# to it is a persistence concern, not a credential-disclosure one, and this
# guard does not claim to stop persistence.)
got, why = ask("cat <<EOF > " + HOME + "/.ssh/id_" + "rsa\nkeymaterial\nEOF")
R.check("redirect target on the opener line is still checked", got == "DENY",
        why.split("\n")[0])


# ---------------------------------------------- path-shaped tokens in prose
# `~/.netrc` in a commit message is prose, and the file it names really does
# exist — so existence alone cannot separate this from an operation. Position
# does: quoted, in a segment with nothing that reads files.
QUOTED_PROSE = [
    ("commit message naming credential paths",
     "git commit -m 'deny reads of .env, ~/.ssh, ~/.netrc and *.pem'"),
    ("echo describing a path", "echo 'we never read ~/.netrc any more'"),
    ("gh pr create body",
     "gh pr create --title x --body 'stops agents reading ~/.ssh/id_rsa'"),
    ("a flag value, not a file", "myprog --note '~/.aws/credentials is blocked'"),
]
for label, cmd in QUOTED_PROSE:
    got, why = ask(cmd)
    R.check("quoted prose allowed: %s" % label, got == "ALLOW",
            why.split("\n")[0])

# The narrowing must not reach a real read, quoted or not.
QUOTED_OPS = [
    ("quoted path given to a reader", 'cat "' + HOME + '/.ssh/id_' + 'rsa"'),
    ("single-quoted path to a reader", "head -c 10 '" + HOME + "/.netrc'"),
    ("quoted path to a searcher", "grep -r x '" + HOME + "/.ssh/id_" + "rsa'"),
    ("unquoted path with no verb at all", HOME + "/.netrc"),
]
for label, cmd in QUOTED_OPS:
    got, why = ask(cmd)
    R.check("still blocked: %s" % label, got == "DENY", why.split("\n")[0])


# A tilde is only "home" at the start of a path. Joining before expanding used
# to produce /home/you/~/... — a path that cannot exist, reported as fact.
got, why = ask("cat ~/.ssh/id_" + "ed25519")
R.check("tilde expanded before resolving", "/~/" not in why, why.split("\n")[0])
R.check("tilde path resolves to the real home", HOME + "/.ssh/id_" in why,
        why.split("\n")[0])

# ------------------------------------- naming a human-only command is not running it
# The path walk learned this first; the verb checks had not. Writing about
# `vlt identity import` in a heredoc comment, or echoing advice about
# `vlt identity export`, is prose. Only a segment that would EXECUTE the text
# counts.
VERB_PROSE = [
    ("human-only command in a heredoc comment",
     "python3 - <<'PY'\n# vlt identity import restores the master key\n"
     "print(1)\nPY"),
    ("human-only command echoed as advice",
     "echo 'run vlt identity export before you wipe the disk'"),
    ("human-only command in a commit message",
     "git commit -m 'document vlt keyring prune in the README'"),
    ("keyring named in prose",
     "echo 'the master key lives in gnome-keyring, never on disk'"),
    ("keyring named in a heredoc comment",
     "cat <<'EOF' > /tmp/notes.md\n# secret-tool is not used any more\nEOF"),
]
for label, cmd in VERB_PROSE:
    got, why = ask(cmd)
    R.check("verb prose allowed: %s" % label, got == "ALLOW", why.split("\n")[0])

# Quoted text that something in the segment will RUN is not prose.
VERB_OPS = [
    ("the command itself", "vlt identity export /tmp/k"),
    ("wrapped in sh -c", "sh -c 'vlt identity export /tmp/k'"),
    ("wrapped in an interpreter",
     "python3 -c 'import secretstorage; print(1)'"),
    ("piped through xargs", "echo x | xargs -I{} vlt get github.com/me"),
    ("keyring tool invoked",
     "secret-tool lookup application vlt purpose master-identity"),
]
for label, cmd in VERB_OPS:
    got, why = ask(cmd)
    R.check("still blocked: %s" % label, got == "DENY", why.split("\n")[0])

got, why = ask("vlt identity export /tmp/k")
R.check("verb denial says which segment matched", "matched in:" in why,
        why.split("\n")[0])


# ------------------------------- a credential directory, with nothing in it yet
# CI found this on its first run: the existence requirement made
# `cd ~/.ssh && cat id_rsa` depend on whether that file happened to be there.
# It was, on the machine the tests were written on. On a fresh runner it was
# not, and evasion_test reported the case it exists to pin as a HOLE.
#
# The fake home the harness builds now contains an id_rsa, so these cases use a
# DIFFERENT, EMPTY .ssh directory. Nothing but the directory rule can block
# them, which is the point: delete that rule and these go red.
emptyssh = os.path.join(tmp, "fresh", ".ssh")
os.makedirs(emptyssh)

got, why = ask("cd " + emptyssh + " && cat id_" + "rsa")
R.check("bare key name blocked inside an empty .ssh", got == "DENY",
        why.split("\n")[0])
R.check("and the message does not claim the file exists",
        "is a credential file" not in why, why.split("\n")[0])
R.check("and it says the directory is the reason",
        "directory" in why, why.split("\n")[0])

got, why = ask("cd " + os.path.join(tmp, "fresh", ".aws") + " && cat credentials")
R.check("same for an .aws directory that does not exist at all", got == "DENY",
        why.split("\n")[0])

# The rule is about credential NAMES in credential directories, not about
# everything in them. An ssh config and a known_hosts file are neither secret
# nor interesting, and blocking them would be the false-positive habit again.
for label, base in (("config", "config"), ("known_hosts", "known_hosts")):
    got, why = ask("cd " + emptyssh + " && cat " + base)
    R.check("still allowed in .ssh: %s" % label, got == "ALLOW",
            why.split("\n")[0])

# And an ordinary directory is unchanged: a bare word there is still prose.
got, why = ask("cd " + tmp + " && cat id_" + "rsa")
R.check("bare key name in an ordinary directory is still prose",
        got == "ALLOW", why.split("\n")[0])


import shutil                                            # noqa: E402
shutil.rmtree(tmp, ignore_errors=True)
sys.exit(R.done())
