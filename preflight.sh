#!/usr/bin/env bash
# Pre-push safety audit. Run from the repo root, BEFORE the first push and before
# any push adding files you did not write line by line.
#
#   bash preflight.sh            # audit working tree + full history
#   bash preflight.sh --tree     # working tree only (faster, less thorough)
#
# Exit code 0 = nothing found. Non-zero = STOP and read the output.
#
# This finds the common cases. It does not replace reading `git status` and
# thinking. A clean run is necessary, not sufficient.

set -uo pipefail
FAIL=0
TREE_ONLY=${1:-}

hit()  { printf '\033[31m  FAIL\033[0m %s\n' "$1"; FAIL=1; }
warn() { printf '\033[33m  WARN\033[0m %s\n' "$1"; }
ok()   { printf '\033[32m  ok  \033[0m %s\n' "$1"; }
sec()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }

[ -d .git ] || { echo "not a git repository"; exit 2; }

# --------------------------------------------------------------------------- #
sec "1. What is about to go"
UNTRACKED=$(git ls-files --others --exclude-standard | head -40)
if [ -n "$UNTRACKED" ]; then
  warn "untracked files present — read every line before 'git add .':"
  echo "$UNTRACKED" | sed 's/^/         /'
else
  ok "no untracked files"
fi

# --------------------------------------------------------------------------- #
sec "2. Key material and credential files"
KEYFILES=$(git ls-files | grep -iE '(^|/)(\.env($|\.)|id_rsa|id_ed25519|.*\.pem$|.*\.p12$|.*\.pfx$|credentials\.json|service-account.*\.json|\.netrc)' || true)
[ -n "$KEYFILES" ] && hit "credential-shaped files are TRACKED:
$(echo "$KEYFILES" | sed 's/^/         /')" || ok "no credential-shaped filenames tracked"

# By content, not by name — catches a private key called anything at all.
KEYBLOBS=$(git grep -lIE 'BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY|BEGIN CERTIFICATE' -- . 2>/dev/null || true)
[ -n "$KEYBLOBS" ] && hit "private key / certificate material in tracked files:
$(echo "$KEYBLOBS" | sed 's/^/         /')" || ok "no key material by content"

# Untracked key material in the tree is one 'git add .' from permanent.
UNKEY=$(git ls-files --others --exclude-standard -z 2>/dev/null | xargs -0 -r grep -lIE 'BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY' 2>/dev/null || true)
[ -n "$UNKEY" ] && hit "UNTRACKED private key sitting in the working tree:
$(echo "$UNKEY" | sed 's/^/         /')
         (move it out of the repo directory entirely)" || ok "no untracked key material"

# --------------------------------------------------------------------------- #
sec "3. High-confidence token shapes"
PAT='AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|sk-[A-Za-z0-9]{32,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|https?://[^/[:space:]]+:[^@[:space:]]+@'
TOK=$(git grep -nIE "$PAT" -- . 2>/dev/null | head -20 || true)
[ -n "$TOK" ] && hit "token-shaped strings in the working tree:
$(echo "$TOK" | sed 's/^/         /')" || ok "no token shapes in tree"

if [ "$TREE_ONLY" != "--tree" ]; then
  HTOK=$(git rev-list --all 2>/dev/null | head -400 | xargs -r git grep -nIE "$PAT" 2>/dev/null | head -20 || true)
  [ -n "$HTOK" ] && hit "token-shaped strings in HISTORY (deleting the file will NOT help — ROTATE):
$(echo "$HTOK" | sed 's/^/         /')" || ok "no token shapes in history"
fi

# --------------------------------------------------------------------------- #
sec "4. Assignments that look like secrets"
ASSIGN=$(git grep -nIE "(api[_-]?key|secret|password|passwd|token|auth)[\"']?\s*[:=]\s*[\"'][^\"']{12,}" -- . 2>/dev/null \
  | grep -viE '(example|placeholder|dummy|your[_-]|xxx|<.*>|\{\{|os\.environ|getenv|process\.env|\$\{)' | head -20 || true)
[ -n "$ASSIGN" ] && hit "secret-looking assignments (check each; use env vars or placeholders):
$(echo "$ASSIGN" | sed 's/^/         /')" || ok "no suspicious assignments"

# --------------------------------------------------------------------------- #
sec "5. Compound documents (PDF / notebooks / office)"
# A live API key was once found on page 12 of a committed report PDF.
PDFS=$(git ls-files '*.pdf' 2>/dev/null || true)
if [ -n "$PDFS" ]; then
  if command -v pdftotext >/dev/null 2>&1; then
    FOUND=""
    while IFS= read -r f; do
      M=$(pdftotext "$f" - 2>/dev/null | grep -inE "$PAT" | head -3 || true)
      [ -n "$M" ] && FOUND="$FOUND
         $f: $M"
    done <<< "$PDFS"
    [ -n "$FOUND" ] && hit "token shapes inside PDFs:$FOUND" || ok "PDFs scanned, clean"
  else
    warn "PDFs tracked but pdftotext not installed — scan them manually:
$(echo "$PDFS" | sed 's/^/         /')"
  fi
else
  ok "no PDFs tracked"
fi

NB=$(git ls-files '*.ipynb' 2>/dev/null | xargs -r grep -l '"output_type"' 2>/dev/null || true)
[ -n "$NB" ] && warn "notebooks with STORED OUTPUT (outputs can contain tokens and data):
$(echo "$NB" | sed 's/^/         /')" || ok "no notebook outputs"

# --------------------------------------------------------------------------- #
sec "6. Personal and locating information"
IMGS=$(git ls-files '*.jpg' '*.jpeg' '*.png' '*.heic' '*.tif' 2>/dev/null || true)
if [ -n "$IMGS" ]; then
  if command -v exiftool >/dev/null 2>&1; then
    GPS=$(echo "$IMGS" | xargs -r exiftool -s -GPSLatitude -GPSLongitude 2>/dev/null | grep -i gps || true)
    [ -n "$GPS" ] && hit "GPS coordinates in committed images — strip EXIF" || ok "no GPS in image EXIF"
  else
    warn "images tracked but exiftool not installed — verify EXIF is stripped"
  fi
else
  ok "no images tracked"
fi

# Recorded data is the leak that looks like a feature. A public repo was found
# serving five real CSV logs off a client's vehicle from a recordings/ folder.
DATA=$(git ls-files '*.csv' '*.tsv' '*.log' '*.parquet' '*.mat' '*.npy' '*.h5' '*.bag' \
       '*.dbc' '*.mf4' '*.blf' 2>/dev/null | head -20 || true)
if [ -n "$DATA" ]; then
  warn "recorded-data files are TRACKED. For EACH one: where did it come from?
         If it came off a real machine, vehicle, patient or customer, it does not
         belong in a public repo — and deleting it later will not unpublish it:
$(echo "$DATA" | sed 's/^/         /')"
else
  ok "no recorded-data files tracked"
fi

DATADIR=$(git ls-files | awk -F/ 'NF>1{print $1}' | sort -u \
          | grep -iE '^(recordings?|data|logs?|captures?|samples?|dataset)$' || true)
[ -n "$DATADIR" ] && warn "data-shaped directories tracked: $(echo "$DATADIR" | tr '\n' ' ')" \
                  || ok "no data-shaped directories"

# Deliberately NOT automated: "does this name a colleague?" was tried as a regex
# and fired on "Steering angle from wheel encoders alone". A check that cries
# wolf gets ignored, taking the real warnings with it. It is on the manual list,
# where it belongs -- and the real instance was in a repo DESCRIPTION on GitHub,
# which no local grep can reach anyway.

AUTHORS=$(git log --format='%an <%ae>' 2>/dev/null | sort -u)
NAUTH=$(echo "$AUTHORS" | grep -c . || echo 0)
echo "         authors recorded in history:"
echo "$AUTHORS" | sed 's/^/           /'
if [ "$NAUTH" -gt 1 ]; then
  warn "more than one author identity in history. If these are the same person
         under different names, the informal one is public forever. Fix
         'git config user.name' now; past commits need a history rewrite."
else
  ok "single consistent author identity"
fi

# --------------------------------------------------------------------------- #
sec "7. Housekeeping"
{ [ -f LICENSE ] || [ -f LICENSE.md ]; } && ok "LICENSE present" \
  || hit "no LICENSE — nobody may legally use this"
[ -f .gitignore ] && ok ".gitignore present" || hit "no .gitignore"
[ -f README.md ] && ok "README.md present" || hit "no README.md"

CLAUDE=$(git log --format='%an%n%ae%n%B' 2>/dev/null | grep -icE 'claude|anthropic|co-authored-by: *claude' || true)
[ "${CLAUDE:-0}" -gt 0 ] && hit "history mentions Claude/Anthropic — must never appear" \
                         || ok "no AI attribution in history"

BIG=$(git ls-files -z 2>/dev/null | xargs -0 -r du -k 2>/dev/null | awk '$1>5000{print $1" KB  "$2}' | head -5 || true)
[ -n "$BIG" ] && warn "large files (>5 MB) — do they belong in git?
$(echo "$BIG" | sed 's/^/         /')" || ok "no oversized files"

# --------------------------------------------------------------------------- #
sec "8. External scanners"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --no-banner --redact -v >/dev/null 2>&1 && ok "gitleaks clean" || hit "gitleaks found something — run: gitleaks detect --redact -v"
else
  warn "gitleaks not installed (recommended: it catches shapes this script does not)"
fi

# --------------------------------------------------------------------------- #
printf '\n'
if [ "$FAIL" -eq 0 ]; then
  printf '\033[32m== automated checks passed ==\033[0m\n'
  cat <<'MANUAL'

Still to do BY HAND — the script cannot judge these:

  [ ] no client/employer names, logos, ticket IDs, or field data
  [ ] no constants FITTED to private data (a tuned number is private info)
  [ ] the repo DESCRIPTION and topics name no third party, and still match
      what the code actually does
  [ ] every OTHER public repo on this account has had this same look — the
      dangerous one is the old repo nobody has opened in years
  [ ] nothing that locates a person: address, city, timezone, schedule
  [ ] every vendored asset is licensed for redistribution
  [ ] screenshots contain no tokens, real paths, or personal notifications
  [ ] you have the RIGHT to publish this (authorship != copyright)
  [ ] repo visibility is the one you intend

If a credential was ever pushed: ROTATE IT FIRST. Cleaning history is
housekeeping done afterwards, not a remedy.
MANUAL
else
  printf '\033[31m== FAILURES ABOVE — DO NOT PUSH ==\033[0m\n'
fi
exit "$FAIL"
