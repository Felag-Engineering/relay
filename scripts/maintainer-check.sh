#!/usr/bin/env bash
# Decide whether a GitHub account is a maintainer, for the routines that read GitHub text.
#
#   scripts/maintainer-check.sh <login>
#
# A routine with push access must not take instructions from an arbitrary commenter once the
# repo is public. This is the one check every routine runs on an author before that author's
# text may instruct it; the rule, and what each routine does with the answer, is
# docs/agents/routines.md#who-may-instruct-a-routine. This script is the only implementation.
#
# A maintainer is an account whose EFFECTIVE role_name, from
# repos/{owner}/{repo}/collaborators/<login>/permission, is exactly admin, maintain or write.
# The role is effective, so a team granted write or higher counts. triage, read, custom roles
# and anything unrecognised are refused (fail closed). role_name decides, never the legacy
# `permission` field, which folds maintain into write and triage into read.
#
# Exit contract (every caller branches on it):
#   0  maintainer        stdout `maintainer: <login> (<role>)`
#   1  not a maintainer  stdout `not a maintainer: <login> (<reason>)`; reason is `role <r>`,
#                        `role not admitted`, `app account` or `no such user`
#   2  the check could not run; stderr `maintainer-check: could not run: <reason>`, nothing on
#      stdout. EXIT 2 IS NEITHER ANSWER: a caller must escalate it, never read it as "not a
#      maintainer" and never as "maintainer". A routine that cannot tell an outsider from a
#      maintainer must not guess either way (as security-surface.sh's exit 2 is never "clean").
#
# <login> is the REST form, `.user.login` (an app is `<slug>[bot]`). The GraphQL form that
# `gh ... --json author` returns renders an app as `app/<slug>`; its slash fails validation and
# exits 2, so a caller that read the wrong field escalates loudly instead of being silently
# admitted or refused. The whole string is validated before any call.
#
# A 404 from the permission endpoint is disambiguated through users/<login>: a 404 for a user
# that does not exist is "no such user" (exit 1); a 404 for a user that exists means the token
# cannot see the collaborator list, which is not evidence of "outsider" (exit 2).
#
# App accounts (`<slug>[bot]`) are refused without a call: a GitHub App's comment is never a
# maintainer's instruction, and bots do comment on loop PRs, so this is an ordinary "not
# actioned", not an escalation. A bot whose login lacks the suffix is the caller's to catch
# from the REST `.user.type` (docs/agents/routines.md).
#
# Output is only the one line above; a response body or an unadmitted role string is never
# echoed. Nothing is read from stdin.
#
# Residual limits, stated so they are not mistaken for coverage:
#   - custom roles are refused, even a custom role built on write.
#   - a deleted account (REST `ghost`, or `user: null` projected to an empty login) cannot be
#     checked: it exits 2. Noisy, never permissive.
#   - the repo is the one `gh` resolves for {owner}/{repo}: the cwd's remote, or GH_REPO.
set -uo pipefail
export LC_ALL=C

die() {
  echo "maintainer-check: could not run: $1" >&2
  exit 2
}

[ "$#" -eq 1 ] || die "usage: maintainer-check.sh <login>"
login="$1"

if [[ $login =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}\[bot\]$ ]]; then
  echo "not a maintainer: $login (app account)"
  exit 1
fi

if [ "${#login}" -lt 1 ] || [ "${#login}" -gt 39 ] ||
  ! [[ $login =~ ^[A-Za-z0-9]([A-Za-z0-9]|-[A-Za-z0-9])*$ ]]; then
  die "malformed login"
fi

command -v gh >/dev/null 2>&1 || die "gh not found"

ERRFILE="$(mktemp)" || die "mktemp failed"
trap 'case "${ERRFILE:-}" in /*) rm -f "$ERRFILE" ;; esac' EXIT
case "$ERRFILE" in
  /*) ;;
  *)
    ERRFILE=""
    die "mktemp returned a non-absolute path"
    ;;
esac

# The status gh prints as `(HTTP nnn)` on stderr, or empty.
http_code() {
  grep -oE '\(HTTP [0-9]{3}\)' "$ERRFILE" | head -n 1 | grep -oE '[0-9]{3}'
}

role="$(gh api "repos/{owner}/{repo}/collaborators/${login}/permission" --jq '.role_name' 2>"$ERRFILE")"
rc=$?

if [ "$rc" -eq 0 ]; then
  case "$role" in
    admin | maintain | write)
      echo "maintainer: $login ($role)"
      exit 0
      ;;
    "" | null) die "no role_name in response" ;;
  esac
  if [[ $role =~ ^[a-z_-]{1,32}$ ]]; then
    echo "not a maintainer: $login (role $role)"
  else
    echo "not a maintainer: $login (role not admitted)"
  fi
  exit 1
fi

code="$(http_code)"
if [ "$code" != "404" ]; then
  die "permission lookup failed${code:+ (HTTP $code)}"
fi

gh api "users/${login}" --jq '.login' >/dev/null 2>"$ERRFILE"
rc=$?
if [ "$rc" -eq 0 ]; then
  die "permission endpoint returned 404 for an existing user"
fi
if [ "$(http_code)" = "404" ]; then
  echo "not a maintainer: $login (no such user)"
  exit 1
fi
die "user lookup failed"
