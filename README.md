# agent-vault

**One encrypted store for every credential, and a guard that lets coding agents
*use* secrets without ever *seeing* them.**

An agent can discover that a GitHub token exists, check that it starts `ghp_` and
is 40 characters, and run `gh` with it in the environment — without the value
ever entering the conversation, a log, or a file it can read back. If a
credential is missing, the agent asks, and a window opens for you to type it in.

Reading `.env`, `~/.ssh`, `~/.netrc` and `*.pem` is blocked at the tool layer, so
it does not depend on the model choosing to comply.

```
 vlt — credential vault
 ▾ vps                            │ vps/senko/3x-ui
   ▾ senko                        │ type vpn        account senko
     ● 3x-ui                      │
     ● ssh                        │ FIELD         VALUE                STATE
   ▸ frankfurt                    │ username      admin                shown
 ▾ cloudflare                     │ password      oZSy••••••••         masked
   ● example                      │ panel         http••••••••         masked
                                  │ API_token     Kra9••••••••         masked
 ↑↓ move  TAB pane  SPACE mask  v reveal  e edit  a add  m move  d delete  q quit
```

## Why

Agents need credentials, and the two usual answers both leak. Pasting a value
into the chat puts it in the transcript for good. A `.env` the agent can read is
plaintext on disk that every agent can read all of.

Telling the agent not to look does not work:
[claude-code#44868](https://github.com/anthropics/claude-code/issues/44868) is
Claude Code reading `.env` via `grep -n` *despite* a `CLAUDE.md` rule forbidding
it. An instruction is not a control, so this ships a control.

## Install

Requires Python ≥ 3.8, the `cryptography` package, and a Secret Service keyring
(gnome-keyring or equivalent).

```bash
git clone https://github.com/<user>/agent-vault
cd agent-vault
./install.sh
```

The installer checks requirements, installs the `vlt` command, creates the vault,
and — if it finds `~/.claude` — registers the guard hook and the agent skill.
Re-running is safe; it never touches an existing vault and backs up anything it
replaces. `./install.sh --uninstall` reverses it and leaves your vault alone.

**Back up the master key immediately.** Without it every secret is unrecoverable:

```bash
VLT_HUMAN=1 vlt identity export ~/vlt-master-key.txt   # then move it offline
```

## Use

```bash
vlt ui                                   # browse: tree, fields, masking
vlt list                                 # what exists — names, no values
vlt peek github.com/me                   # structure: length, charset, first chars
vlt exec github.com/me -- gh repo list   # inject into a child process
vlt file ssh/box key --out ~/.ssh/k --mode 0600
vlt render --secret openai.com/me --out ./.env
vlt request stripe.com/me --fields key --reason "deploy needs the live key"
vlt audit --tail 20                      # who read what, when, from which session
```

`peek` is the one that makes this workable — an agent can confirm a credential
has the right shape before spending a run on it, without being handed the value:

```
hidden   : key, password, secret, token
token:       ghp_••••••••••••   [40 chars, base64url]
username:    exampleuser        [11 chars, base62]
```

Masking is **fail-closed**: everything is hidden except addressing fields
(`username host port region account_id path`), so a field the schema has never
seen — `API_token`, `reality`, a webhook URL — is masked without you thinking
about it. Change it per record with `vlt hide` / `vlt unhide`, or `SPACE` in the UI.

## One record shape for everything

An SSH login and a Stripe key look identical to whatever consumes them:

```json
{
  "name": "vps/frankfurt/3x-ui",
  "type": "vpn",
  "fields": {"username": "…", "password": "…", "host": "…", "port": "…"},
  "env_map": {"VPS_PASSWORD": "password", "VPS_HOST": "host"},
  "hidden": ["password"],
  "tags": ["panel"], "notes": ""
}
```

- **Fields** are a closed vocabulary: `username password token key secret host
  port url path region account_id`. Anything else goes in `extra` — still masked.
- **Names** are `<provider>/<account>[/<purpose>]`. For several machines running
  the same service, put the machine second and the service third:
  `vps/frankfurt/ssh`, `vps/frankfurt/3x-ui`, `vps/helsinki/ssh`. Then
  `vlt list frankfurt` shows one machine and `vlt list 3x-ui` every panel.

## What agents can and cannot do

| Agents may | Agents may not |
|---|---|
| `list`, `peek`, `audit`, `scan` | `get`, `show`, `set`, `add`, `import`, `rm` |
| `exec`, `file`, `render` | change what is masked (`hide`/`unhide`) |
| `request` a missing credential | read `.env`, `~/.ssh`, `~/.netrc`, `*.pem` |
| | search the disk for key material |
| | read a file `vlt` just rendered |
| | edit the guard, the CLI or the policy |

Human-only commands need a real terminal or a desktop confirmation — setting
`VLT_HUMAN=1` in a script is not enough, because an environment variable is not
proof that a person is present.

You control enforcement: `vlt guard warn` logs instead of denying, `vlt guard
off` disables it, `vlt guard on` restores it.

## Integrations

**Claude Code** is fully supported: the guard runs as a `PreToolUse` hook, which
is what makes the restrictions real rather than advisory. `integrations/claude-code/`
holds the hook and the agent-facing skill.

**Other agents** — Codex CLI, opencode, Cursor — can use the `vlt` CLI, and the
`peek`/`exec`/`request` protocol works anywhere. **But the enforcement does not
port.** Without a pre-tool hook, nothing stops that agent reading `~/.ssh`
directly, and the guarantees in this README do not hold. Do not assume otherwise
because the CLI runs. See `integrations/README.md`.

## Testing

```bash
python3 tests/run_all.py            # everything
python3 tests/run_all.py --fast     # skip the pty UI suites
```

13 suites, run against a throwaway vault in a temp directory — never your real
one, and never your keyring.

The two that matter most:

- **`evasion_test.py`** — 20 adversarial bypasses of the bash guard: quote
  splitting (`c""at`), backslash escapes, `cd` then a relative path, `xargs`,
  here-strings, base64 piped to a shell, runtime-constructed paths. Every case
  that flips to ALLOW is a real hole. Add to it rather than weakening it.
- **`prose_test.py`** — the guard must not fire on English. Built from a real
  false denial: the word `credentials` in a comment, inside a heredoc bound for a
  remote host, was resolved against the cwd and refused with a message asserting
  a file existed that did not. False positives on prose train agents to dodge
  patterns, which is the behaviour the guard exists to suppress.

## Limits

**This is not a sandbox.** An adversarial agent with unrestricted `Bash` running
as your user can eventually do anything you can, including reading the master key
from the keyring. The guard raises the cost and records the attempt.

The bash guard is regex over command text. It blocks all 20 known evasions today;
shell is not a regular language and no such matcher is complete.

**Linux only, in practice.** It needs a Secret Service keyring, and `vlt request`
wants `gnome-terminal` or `zenity`. There is no macOS Keychain backend yet. If no
keyring is found, `vlt` refuses to start rather than silently writing the key to
disk.

Full detail: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## Recovering without this tool

The format is deliberately plain — `b"VLT1"` + 12-byte nonce + AES-256-GCM
ciphertext, record name as associated data, subkey
`HKDF-SHA256(master, salt="vlt-record-v1", info=<name>)`:

```python
import base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

name   = "github.com/me"
master = base64.b64decode("<the VLT-MASTER-V1 line from your key backup>")
blob   = open("/home/you/.local/share/vlt/store/%s.vlt" % name, "rb").read()

key = HKDF(algorithm=hashes.SHA256(), length=32,
           salt=b"vlt-record-v1", info=name.encode()).derive(master)
print(json.loads(AESGCM(key).decrypt(blob[4:16], blob[16:], name.encode())))
```

## Licence

MIT — see [LICENSE](LICENSE).
