#!/usr/bin/env bash
# Proves scripts/maintainer-check.sh decides the way its header claims: exactly role_name
# admin/maintain/write is a maintainer; a non-collaborator is refused (exit 1); a check that
# could not run (exit 2) is told apart from both answers; the login is validated before any
# call; and the login form the routines' commands read (REST `.user.login`) is the one the
# script accepts. The drift guard keeps the prose in docs/agents/routines.md and the commands
# from drifting away from the projections proved here (#910).
#
# Hermetic: a stub `gh` under a throwaway WORKDIR; bash, jq and grep; no network, no GitHub
# token. jq is required, as in vuln-gate-test.sh. Writes nothing outside its own `mktemp -d`.
#
# NOT `set -e`: every case must run and be reported (security-surface-test.sh:12).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "FAIL: jq is required" >&2
  exit 1
fi

SCRIPT="$REPO_ROOT/scripts/maintainer-check.sh"
BIN="$WORKDIR/bin"
EMPTY_BIN="$WORKDIR/empty"
GH_LOG="$WORKDIR/gh.log"
mkdir -p "$BIN" "$EMPTY_BIN"
fail=0

# The stub answers ONLY the two calls the script may make. The literal {owner}/{repo} also
# asserts that the script never interpolates a repo itself. Real jq applies the script's --jq
# expression to the fixture body, so the script's projection is exercised.
cat >"$BIN/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_LOG"
respond() { # <status> <body> <jq expr>
  case "$1" in
    200) printf '%s' "$2" | jq -r "$3" ;;
    404 | 403 | 401 | 500)
      echo '{"message":"stub"}'
      echo "gh: stub error (HTTP $1)" >&2
      return 1
      ;;
    neterr)
      echo "error connecting to api.github.com" >&2
      return 1
      ;;
  esac
}
if [ "${1:-}" = api ] && [ "${3:-}" = --jq ]; then
  case "$2" in
    "repos/{owner}/{repo}/collaborators/"*"/permission")
      respond "${STUB_PERM_STATUS:-200}" "${STUB_PERM_BODY:-}" "$4"
      exit $?
      ;;
    users/*)
      L="${2#users/}"
      respond "${STUB_USER_STATUS:-200}" "{\"login\":\"$L\"}" "$4"
      exit $?
      ;;
  esac
fi
echo "UNEXPECTED: $*" >>"$GH_LOG"
exit 99
STUB
chmod +x "$BIN/gh"

# Per-case environment for the stub; run resets it.
ENVV=()
OUT="" ERR="" RC=0

# run <name> <want_rc> <args...>: run the real script and assert the exit contract.
run() {
  local name="$1" want="$2"
  shift 2
  : >"$GH_LOG"
  OUT="$(env -u GH_TOKEN -u GITHUB_TOKEN -u GH_REPO PATH="$BIN:$PATH" GH_LOG="$GH_LOG" \
    ${ENVV[@]+"${ENVV[@]}"} bash "$SCRIPT" "$@" 2>"$WORKDIR/err")"
  RC=$?
  ERR="$(cat "$WORKDIR/err")"
  ENVV=()
  local bad=""
  [ "$RC" -eq "$want" ] || bad="rc=$RC, want rc=$want"
  case "$want" in
    0) [[ $OUT == "maintainer: "* ]] || bad="$bad; stdout lacks 'maintainer: ' prefix"
       [ -z "$ERR" ] || bad="$bad; stderr not empty" ;;
    1) [[ $OUT == "not a maintainer: "* ]] || bad="$bad; stdout lacks 'not a maintainer: ' prefix"
       [ -z "$ERR" ] || bad="$bad; stderr not empty" ;;
    2) [ -z "$OUT" ] || bad="$bad; stdout not empty"
       [[ $ERR == "maintainer-check: could not run: "* ]] || bad="$bad; stderr lacks the could-not-run prefix" ;;
  esac
  if grep -q '^UNEXPECTED' "$GH_LOG"; then
    bad="$bad; unexpected gh call"
  fi
  if [ -n "$bad" ]; then
    echo "FAIL: $name:$bad (stdout='$OUT' stderr='$ERR')" >&2
    fail=$((fail + 1))
    return 1
  fi
  echo "PASS: $name"
}

# check <name> <condition result>: an extra assertion on the last run.
check() {
  local name="$1"
  shift
  if "$@"; then
    echo "PASS: $name"
  else
    echo "FAIL: $name (stdout='$OUT' stderr='$ERR')" >&2
    fail=$((fail + 1))
  fi
}
out_is() { [ "$OUT" = "$1" ]; }
gh_calls() { [ "$(grep -c . "$GH_LOG")" -eq "$1" ]; }
gh_called() { grep -q -- "$1" "$GH_LOG"; }
gh_not_called() { ! grep -q -- "$1" "$GH_LOG"; }

perm() { # <role_name> [<permission>]
  printf '{"permission":"%s","role_name":"%s","user":{"login":"x"}}' "${2:-$1}" "$1"
}
with_perm() { ENVV=(STUB_PERM_STATUS=200 "STUB_PERM_BODY=$1"); }

# --- Admitted roles ---------------------------------------------------------------------
for role in admin maintain write; do
  with_perm "$(perm "$role")"
  run "admits role_name $role" 0 octo-dev
  check "role $role reports the role" out_is "maintainer: octo-dev ($role)"
done

# --- The non-collaborator fixture -------------------------------------------------------
with_perm '{"permission":"read","role_name":"read","user":{"login":"outsider"}}'
run "refuses a non-collaborator" 1 outsider
check "non-collaborator stdout names the role" out_is "not a maintainer: outsider (role read)"
check "non-collaborator makes exactly one call" gh_calls 1
check "non-collaborator triggers no users/ lookup" gh_not_called "users/"

# --- Other refusals ---------------------------------------------------------------------
for role in triage none write-plus; do
  with_perm "$(perm "$role")"
  run "refuses role_name $role" 1 octo-dev
done
with_perm "$(perm Write)"
run "refuses Write (case-exact)" 1 octo-dev
with_perm "$(perm 'admin ')"
run "refuses 'admin ' with a trailing space" 1 octo-dev
with_perm "$(perm read admin)"
run "role_name decides, not permission" 1 octo-dev
check "permission admin with role_name read is a read" out_is "not a maintainer: octo-dev (role read)"

# --- 404 disambiguation -----------------------------------------------------------------
ENVV=(STUB_PERM_STATUS=404 STUB_USER_STATUS=404)
run "permission 404 + user 404 is no such user" 1 ghostly
check "no such user is reported" out_is "not a maintainer: ghostly (no such user)"
check "no such user looked up users/" gh_called "users/ghostly"
for us in 200 500 neterr; do
  ENVV=(STUB_PERM_STATUS=404 "STUB_USER_STATUS=$us")
  run "permission 404 + user $us could not run" 2 octo-dev
  check "permission 404 + user $us looked up users/" gh_called "users/octo-dev"
done

# --- Could not run ----------------------------------------------------------------------
for st in 401 403 500 neterr; do
  ENVV=("STUB_PERM_STATUS=$st")
  run "permission $st could not run" 2 octo-dev
  check "permission $st makes no users/ lookup" gh_not_called "users/"
done
with_perm '{}'
run "200 with no role_name could not run" 2 octo-dev
with_perm '{"permission":"write","role_name":null}'
run "200 with null role_name could not run" 2 octo-dev
with_perm 'not json at all'
run "200 with a non-JSON body could not run" 2 octo-dev
run "no argument could not run" 2
run "two arguments could not run" 2 octo-dev other

# gh absent: the script must say so without needing anything else on PATH.
: >"$GH_LOG"
OUT="$(env -u GH_TOKEN -u GITHUB_TOKEN -u GH_REPO PATH="$EMPTY_BIN" "$BASH" "$SCRIPT" octo-dev 2>"$WORKDIR/err")"
RC=$?
ERR="$(cat "$WORKDIR/err")"
if [ "$RC" -eq 2 ] && [ -z "$OUT" ] && [[ $ERR == "maintainer-check: could not run: gh not found"* ]]; then
  echo "PASS: gh absent could not run"
else
  echo "FAIL: gh absent: rc=$RC stdout='$OUT' stderr='$ERR'" >&2
  fail=$((fail + 1))
fi

# --- Validation before any call ---------------------------------------------------------
with_perm "$(perm write)"
bad_logins=("" "-a" "a-" "a--b" "a/b" "../x" "a b" '$(id)' 'a;b' $'a\nb' "$(printf 'a%.0s' {1..40})" "é")
bad_names=("empty" "leading hyphen" "trailing hyphen" "double hyphen" "slash" "dot-dot path" "space"
  "command substitution" "semicolon" "embedded newline" "40 characters" "non-ASCII letter")
for i in "${!bad_logins[@]}"; do
  with_perm "$(perm write)"
  run "malformed login (${bad_names[$i]}) could not run" 2 "${bad_logins[$i]}"
  check "malformed login (${bad_names[$i]}) makes no call" gh_calls 0
done
with_perm "$(perm write)"
valid39="a-$(printf 'b%.0s' {1..35})-c"
run "39-character login with interior hyphens is admitted" 0 "$valid39"
check "39-character login reaches the stub" gh_calls 1

# --- App accounts -----------------------------------------------------------------------
for app in "dependabot[bot]" "chatgpt-codex-connector[bot]"; do
  with_perm "$(perm write)"
  run "app account $app is refused" 1 "$app"
  check "app account $app makes no call" gh_calls 0
  check "app account $app says so" out_is "not a maintainer: $app (app account)"
done

# --- Output hygiene ---------------------------------------------------------------------
with_perm '{"role_name":"x\nmaintainer: x (admin)"}'
run "an unadmitted multi-line role is refused" 1 octo-dev
check "an unadmitted role string is never echoed" out_is "not a maintainer: octo-dev (role not admitted)"

# --- Caller shapes ----------------------------------------------------------------------
# The two canonical projections, verbatim from docs/agents/routines.md.
ISSUE_AUTHOR_JQ='[(.user.login // ""), (.user.type // "")] | @tsv'
ISSUE_LIST_JQ='.[] | select(.pull_request == null) | [.number, (.user.login // ""), (.user.type // ""), ([.labels[].name] | join(","))] | @tsv'
ISSUE_COMMENTS_JQ='.[] | [.id, (.user.login // ""), (.user.type // ""), .created_at] | @tsv'

author_of() { printf '%s' "$1" | jq -r "$ISSUE_AUTHOR_JQ" | cut -f1; }
type_of() { printf '%s' "$1" | jq -r "$ISSUE_AUTHOR_JQ" | cut -f2; }

# The caller rule from docs/agents/routines.md: an author whose type is not exactly User is an
# app account, refused before the check is invoked.
gated_run() { # <name> <expected rc> <login> <type>
  if [ "$4" != "User" ]; then
    : >"$GH_LOG"
    check "$1 is refused as an app account without the check" true
    check "$1 does not reach gh" gh_calls 0
    return 0
  fi
  run "$1" "$2" "$3"
}

login="$(author_of '{"number":7,"user":{"login":"octo-dev","type":"User"},"labels":[]}')"
with_perm "$(perm write)"
run "caller shape: single issue, human maintainer" 0 "$login"

login="$(author_of '{"number":8,"user":{"login":"dependabot[bot]","type":"Bot"},"labels":[]}')"
with_perm "$(perm write)"
run "caller shape: single issue, bot author" 1 "$login"
check "caller shape: bot author is an app account" out_is "not a maintainer: dependabot[bot] (app account)"
check "caller shape: bot author makes no call" gh_calls 0

login="$(author_of '{"number":9,"user":null,"labels":[]}')"
check "caller shape: user null projects to the empty string" test -z "$login"
with_perm "$(perm write)"
run "caller shape: deleted account (user null) could not run" 2 "$login"
check "caller shape: deleted account makes no call" gh_calls 0

login="$(author_of '{"number":10,"user":{"login":"ghost","type":"User"},"labels":[]}')"
ENVV=(STUB_PERM_STATUS=404 STUB_USER_STATUS=200)
run "caller shape: ghost with 404 and an existing user could not run" 2 "$login"

LIST='[
 {"number":1,"user":{"login":"octo-dev","type":"User"},"labels":[{"name":"loop:ready"}]},
 {"number":2,"user":{"login":"outsider","type":"User"},"labels":[{"name":"loop:ready"},{"name":"idea"}]},
 {"number":3,"user":{"login":"renovate[bot]","type":"Bot"},"labels":[{"name":"loop:ready"}]},
 {"number":4,"user":{"login":"octo-dev","type":"User"},"labels":[{"name":"loop:ready"}],"pull_request":{"url":"x"}}
]'
rows="$(printf '%s' "$LIST" | jq -r "$ISSUE_LIST_JQ")"
check "caller shape: the list yields three rows, the PR item filtered" test "$(grep -c . <<<"$rows")" -eq 3
want_logins=(octo-dev outsider "renovate[bot]")
want_rcs=(0 1 1)
want_roles=(write read write)
i=0
while IFS=$'\t' read -r _num login _labels; do
  check "caller shape: list row $((i + 1)) author is ${want_logins[$i]}" test "$login" = "${want_logins[$i]}"
  with_perm "$(perm "${want_roles[$i]}")"
  run "caller shape: list row $((i + 1)) (${want_logins[$i]})" "${want_rcs[$i]}" "$login"
  i=$((i + 1))
done <<<"$rows"

# A bot with no [bot] suffix whose role would be write: refused on its type alone, in every
# caller shape. The stub would admit the login if the check were reached.
NOSUFFIX_ISSUE='{"number":11,"user":{"login":"Copilot","type":"Bot"},"labels":[{"name":"loop:ready"}]}'
with_perm "$(perm write)"
run "control: the check alone would admit a suffixless login with a write role" 0 Copilot
with_perm "$(perm write)"
gated_run "caller shape: single issue, no-suffix Bot" 1 "$(author_of "$NOSUFFIX_ISSUE")" "$(type_of "$NOSUFFIX_ISSUE")"
check "caller shape: single issue Bot type projects as Bot" test "$(type_of "$NOSUFFIX_ISSUE")" = Bot
for odd in '"type":"Organization"' '"type":null' ''; do
  odd_issue="{\"number\":12,\"user\":{\"login\":\"Copilot\"${odd:+,}$odd},\"labels\":[]}"
  with_perm "$(perm write)"
  gated_run "caller shape: single issue, type '${odd:-missing}'" 1 "$(author_of "$odd_issue")" "$(type_of "$odd_issue")"
done

row="$(printf '[%s]' "$NOSUFFIX_ISSUE" | jq -r "$ISSUE_LIST_JQ")"
IFS=$'\t' read -r _num login btype _labels <<<"$row"
check "caller shape: list row projects the Bot type as field 3" test "$btype" = Bot
with_perm "$(perm write)"
gated_run "caller shape: issue list, no-suffix Bot" 1 "$login" "$btype"

COMMENTS='[{"id":5,"user":{"login":"Copilot","type":"Bot"},"created_at":"2026-01-01T00:00:00Z"}]'
row="$(printf '%s' "$COMMENTS" | jq -r "$ISSUE_COMMENTS_JQ")"
IFS=$'\t' read -r _id login btype _at <<<"$row"
check "caller shape: comment row projects the Bot type as field 3" test "$btype" = Bot
with_perm "$(perm write)"
gated_run "caller shape: comment listing, no-suffix Bot" 1 "$login" "$btype"

with_perm "$(perm write)"
gated_run "caller shape: comment listing, human maintainer still checked" 0 octo-dev User

# The GraphQL form, which `gh ... --json author` returns for an app, must escalate.
with_perm "$(perm write)"
run "caller shape: GraphQL app/<slug> could not run" 2 "app/dependabot"
check "caller shape: GraphQL form makes no call" gh_calls 0

# --- Drift guard ------------------------------------------------------------------------
# The prose callers copy the projections verbatim. The single-issue projection is matched with
# its --jq flag: bare, it is a substring of the comment-listing projections.
ISSUE_AUTHOR_ARG="--jq '$ISSUE_AUTHOR_JQ'"
guard_has() { # <needle> <file...>
  local needle="$1" f
  shift
  for f in "$@"; do
    if grep -qF -- "$needle" "$REPO_ROOT/$f"; then
      echo "PASS: drift guard: $f carries $needle"
    else
      echo "FAIL: drift guard: $f does not carry: $needle" >&2
      fail=$((fail + 1))
    fi
  done
}
guard_has "$ISSUE_AUTHOR_ARG" docs/agents/routines.md .claude/commands/dev-loop.md \
  .claude/commands/dev-loop-parallel.md .claude/commands/pr-respond.md
guard_has "$ISSUE_LIST_JQ" docs/agents/routines.md .claude/commands/dev-loop-queue.md
guard_has "$ISSUE_COMMENTS_JQ" docs/agents/routines.md .claude/commands/dev-loop.md \
  .claude/commands/pr-respond.md
# Each issue-author caller states the type gate (not exactly `User` is an app account).
guard_has "not exactly \`User\`" .claude/commands/dev-loop.md .claude/commands/dev-loop-queue.md \
  .claude/commands/dev-loop-parallel.md .claude/commands/pr-respond.md docs/agents/routines.md
# Every open-PR listing the gated commands take (capacity, duplicate guard, branch list, PR
# selection) is the paginated REST pulls listing with the same-repository filter, which fails
# closed on a head with no repository; `gh pr list` is capped at 30 and would let fork PRs
# push real ones off the page.
SAME_REPO_FILTER='select(.head.repo != null and .head.repo.full_name == .base.repo.full_name)'
guard_has "gh api --paginate 'repos/{owner}/{repo}/pulls?state=open&per_page=100'" \
  .claude/commands/dev-loop.md .claude/commands/dev-loop-queue.md .claude/commands/pr-respond.md
guard_has "$SAME_REPO_FILTER" .claude/commands/dev-loop.md .claude/commands/dev-loop-queue.md \
  .claude/commands/pr-respond.md
for f in dev-loop dev-loop-queue pr-respond; do
  if grep -n 'gh pr list' "$REPO_ROOT/.claude/commands/$f.md" >"$WORKDIR/drift"; then
    echo "FAIL: drift guard: .claude/commands/$f.md lists PRs with the 30-row gh pr list:" >&2
    sed 's/^/    /' "$WORKDIR/drift" >&2
    fail=$((fail + 1))
  else
    echo "PASS: drift guard: .claude/commands/$f.md does not use gh pr list"
  fi
done
# A fork PR's commit messages are never fetched in the same call as the fork flag.
if grep -nE 'gh pr view.*isCrossRepository,' "$REPO_ROOT/.claude/commands/pr-respond.md" >"$WORKDIR/drift"; then
  echo "FAIL: drift guard: pr-respond.md fetches isCrossRepository together with other fields" >&2
  fail=$((fail + 1))
else
  echo "PASS: drift guard: pr-respond.md reads the fork flag alone first"
fi
# No gated command requests the GraphQL author field, nor fetches every comment or review body
# unfiltered through `--json`.
for f in dev-loop dev-loop-queue dev-loop-parallel pr-respond; do
  if grep -nE -- '--json[^|]*(author|comments|reviews)' "$REPO_ROOT/.claude/commands/$f.md" >"$WORKDIR/drift"; then
    echo "FAIL: drift guard: .claude/commands/$f.md requests an unfiltered author, comments or reviews field:" >&2
    sed 's/^/    /' "$WORKDIR/drift" >&2
    fail=$((fail + 1))
  else
    echo "PASS: drift guard: .claude/commands/$f.md reads no unfiltered author, comments or reviews"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail case(s) failed" >&2
  exit 1
fi
echo "OK: maintainer-check self-test passed"
