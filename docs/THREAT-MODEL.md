# Threat model

What this tool does and does not defend against. Read this before trusting it
with anything that matters.

## The problem it addresses

A coding agent needs credentials to do useful work — a GitHub token, an SSH
login, a database URL. The two usual answers are both bad:

- **Paste the value into the conversation.** It is now in the transcript, in
  whatever logs the transcript passes through, and in the model's context for
  the rest of the session.
- **Put it in a `.env` the agent can read.** Now it is in plaintext on disk, and
  every agent that touches the project can read all of it, forever.

Agents also *look*. Given a task that needs a credential and no obvious source,
an agent will grep for one. [claude-code#44868][issue] documents Claude Code
reading `.env` via `grep -n` despite a `CLAUDE.md` rule forbidding it — an
instruction is not a control.

[issue]: https://github.com/anthropics/claude-code/issues/44868

## What the design assumes

- **The user is trusted.** This protects credentials from agents and from
  accidents, not from the person at the keyboard.
- **The machine is not already compromised.** A keylogger or a root-level
  attacker defeats everything here.
- **The agent is capable but not adversarial.** It follows instructions, makes
  mistakes, and may be steered by a prompt injection into *trying* something —
  but it is not a determined attacker writing custom code to defeat the guard.
  This is the assumption that most limits the guarantees below; see
  [What it does not stop](#what-it-does-not-stop).

## What it stops

| Threat | Mechanism |
|---|---|
| Secret values reaching the transcript | Agents get `peek` (leading characters, length, charset), never the value. `exec`/`file`/`render` move a value without displaying it. |
| An agent reading `.env`, `~/.ssh`, `~/.netrc`, `*.pem` | A `PreToolUse` hook denies the read before the tool runs. |
| An agent searching the disk for credentials | The hook refuses grep/find patterns that hunt for key material or credential files. |
| One leaked credential exposing the rest | One file per record, each encrypted with its own subkey derived `HKDF-SHA256(master, info=<record name>)`. |
| An agent reading back a file `vlt` just wrote | Rendered paths are registered and then refused. |
| A credential echoed by the process it was injected into | `vlt exec` refuses `env`, `printenv`, `set`, `/proc/self/environ`, and `$VAR` interpolated onto the child's command line. |
| An agent promoting itself with `VLT_HUMAN=1` | Human-only commands additionally require a real terminal or a desktop confirmation. An environment variable is not proof of a person. |
| An agent disabling the guard | The hook refuses edits to itself, the CLI and the policy file. |
| A field nobody anticipated leaking | Masking is fail-closed: everything is hidden except addressing fields, so an unrecognised field name is masked by default. |
| Silent access | Every read, injection and denial is appended to `audit.log` with the session id that caused it. |

## What it does not stop

**A deliberately adversarial agent with unrestricted `Bash` running as your
user.** Anything you can do, such a process can eventually do — including
reading the master key from the keyring and writing its own decryptor. The guard
raises the cost and records the attempt; it is not a sandbox.

Specifically:

- **The bash guard is regex over command text.** It was tested against 20
  evasions (quote splitting, backslash escapes, `cd` then a relative path,
  `xargs`, here-strings, base64-piped-to-shell, runtime-constructed paths) and
  currently blocks all of them — see `tests/evasion_test.py`. That is a strong
  lock on a door, not a wall. Shell is not a regular language and nobody should
  claim otherwise.
- **Inline interpreter code that builds a path at runtime** is refused wholesale
  rather than analysed, because it cannot be analysed. That is a usability cost
  accepted deliberately.
- **The hook reads command text, not file contents.** An agent can write a
  script and run it. The CLI's own refusals still apply — which is why
  human-only commands check for a terminal rather than trusting an environment
  variable.
- **A prompt injection can still cause damage that is not credential theft** —
  deleting files, pushing bad code, calling an API destructively. This tool is
  about credentials only.
- **The vault does not protect against you.** `vlt get` prints values, by design.

### The gap that would close it

Run agents under a **separate uid** that cannot read `~/.local/share/vlt`, and
expose only `vlt` through a setgid wrapper. That moves enforcement from the
agent harness into the kernel, and turns "no realistic leak" into "cannot read
the bytes". Not implemented here.

## Cryptography

- **AES-256-GCM**, one file per record. 12-byte random nonce per write.
- **Per-record subkey**: `HKDF-SHA256(master, salt="vlt-record-v1",
  info=<record name>)`.
- The **record name is authenticated** as associated data, so a `.vlt` file
  cannot be renamed or swapped for another record's.
- File format: `b"VLT1"` + nonce + ciphertext. Documented so a record is
  recoverable with ~15 lines of Python if this tool disappears — see the README.
- **No custom cryptography.** Everything comes from `cryptography`'s recipes
  layer.

### The master key

Held in the OS keyring (Secret Service / gnome-keyring), so it is not a readable
file. It unlocks with your login session, which is why the tool never asks for a
passphrase — a deliberate trade: convenience over resistance to an attacker who
already has your logged-in session.

If no keyring is available, `vlt` **refuses to start** rather than silently
writing the key to disk. `VLT_ALLOW_FILE_KEY=1` accepts the weaker model
explicitly, and `vlt doctor` reports it as a problem for as long as it is in use.

Each vault gets its own keyring entry, so a second `VLT_HOME` does not silently
share the first one's key.

**Losing the key loses everything.** Back it up:
`VLT_HUMAN=1 vlt identity export <file>`, then move that file offline.

## Reporting a problem

Open an issue. If it is a way to extract a value that the guard should have
stopped, include the exact command — a failing case in `tests/evasion_test.py`
is the most useful form a report can take.
