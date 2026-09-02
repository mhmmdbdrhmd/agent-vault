# Known preflight findings

`preflight.sh` reports two hits in this repository, on every run, for ever. Both
are verified false positives. They are documented here rather than suppressed,
because a secret scanner that has been taught to stay quiet is worse than one
that is noisy — and because a reviewer should be able to check this claim in
under a minute rather than trust it.

If you see any finding **other than these two**, stop and treat it as real.

## Finding: "private key / certificate material in tracked files"

### `preflight.sh:41`

```sh
KEYBLOBS=$(git grep -lIE 'BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY|BEGIN CERTIFICATE' ...
```

This is the scanner's own detection pattern. It matches itself.

### `tests/hooktest.py`

```python
("Bash", {"command": "grep -r 'BEGIN RSA PRIVATE KEY' " + H}, "DENY"),
```

A test case asserting that an agent searching the filesystem for private-key
material is **denied**. The string is the thing being tested for.

## Why these are not key material

Real PEM key material is a header line followed by a long base64 body. Neither
hit has one. Verify it yourself — this prints the matching lines and flags any
base64 body that follows within three lines:

```bash
python3 - <<'PY'
import re
PAT = re.compile(r"BEGIN[ A-Z]*PRIVATE KEY|BEGIN CERTIFICATE")
for f in ("preflight.sh", "tests/hooktest.py"):
    lines = open(f, errors="ignore").read().split("\n")
    for i, line in enumerate(lines):
        if PAT.search(line):
            print("%s:%d  %s" % (f, i + 1, line.strip()[:100]))
            for j in range(i + 1, min(i + 4, len(lines))):
                if re.fullmatch(r"[A-Za-z0-9+/=]{40,}", lines[j].strip()):
                    print("   !! base64 body at line %d — REAL KEY" % (j + 1))
PY
```

Expected output: the two lines above, and no `!!`.

## Why this is not fixed by rewriting the code

The obvious "fix" is to assemble those strings from fragments so the scanner
stops matching — `"BEGIN " + "RSA PRIVATE KEY"`. That makes the code worse to
read, and it is exactly the pattern-dodging habit this project argues against
elsewhere: `tests/prose_test.py` exists because false positives that push people
into evasion are a design failure, not a nuisance.

A security tool's source contains the shapes it looks for. That is unavoidable,
and the honest handling is to say so.

## The author-identity check

On a repository with no commits yet, `preflight.sh` prints

```
preflight.sh: line 138: [: 0\n0: integer expression expected
```

because the author list is empty. It resolves after the first commit. Harmless,
and a bug in the shared template rather than in this repo.
