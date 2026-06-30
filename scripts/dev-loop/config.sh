# shellcheck shell=bash
# scripts/dev-loop/config.sh
#
# All tunables for the autonomous dev-loop live here. This file is sourced by
# every other script. Keep it free of logic — declarations only.
#
# SECURITY NOTE: this file is itself a security-sensitive path (see SECURITY_GLOBS
# below). The loop will refuse to auto-merge any change that touches it; edits to
# the gate must be reviewed by a human. That is intentional — the loop must not be
# able to relax its own guardrails unattended.

# --- Repository ---------------------------------------------------------------
REPO_SLUG="${REPO_SLUG:-Felag-Engineering/gleipnir-relay}"
MAIN_BRANCH="${MAIN_BRANCH:-main}"

# --- Toolchain PATH -----------------------------------------------------------
# Schedulers (cron, systemd timers, Claude routines) run NON-login shells that
# don't source ~/.profile or ~/.cargo/env, so `make` can't find go/cargo/buf even
# when they're installed. lib.sh prepends any of these that exist to PATH, so the
# loop is self-sufficient. Add locations here if your toolchains live elsewhere.
TOOLCHAIN_PATHS="${TOOLCHAIN_PATHS:-/usr/local/go/bin:$HOME/.cargo/bin:$HOME/go/bin:$HOME/.local/bin}"

# --- What milestone is the loop working? --------------------------------------
# Matches a GitHub milestone title. Only issues in this milestone are worked.
# Advance this by hand after a human milestone-acceptance review (human seam #3).
ACTIVE_MILESTONE="${ACTIVE_MILESTONE:-v0.0.1}"

# --- Labels (state machine) ---------------------------------------------------
LABEL_READY="loop:ready"            # eligible to be picked up
LABEL_INPROGRESS="loop:in-progress" # currently being worked by a tick
LABEL_NEEDS_HUMAN="loop:needs-human" # escalated — a human must review/merge
LABEL_BLOCKED="loop:blocked"        # waiting on a dependency; skipped by select
LABEL_DONE="loop:done"              # merged (issue also closed by the PR)

# --- Caps & safety rails ------------------------------------------------------
MAX_TICKS="${MAX_TICKS:-1}"             # loop.sh: how many issues per invocation (serial)
IMPL_REPAIR_ATTEMPTS="${IMPL_REPAIR_ATTEMPTS:-1}"  # extra claude tries to reach green
MAX_AUTO_MERGE_LINES="${MAX_AUTO_MERGE_LINES:-600}" # diffs bigger than this escalate
CLAUDE_TIMEOUT_SECS="${CLAUDE_TIMEOUT_SECS:-2400}"  # per claude -p call

# Treat issue order as a dependency chain: only ever work the LOWEST-numbered open
# issue in the milestone, and only if it's ready. This stops the loop starting a
# dependent issue (e.g. the Relay) before its predecessor's escalated PR (e.g. the
# proto codegen) is merged into main — the loop branches off main, so it would
# otherwise build against a tree missing the dependency. Set 0 for the looser
# "pick the lowest READY issue, skipping blocked/escalated ones" behaviour.
LOOP_STRICT_ORDER="${LOOP_STRICT_ORDER:-1}"

# --- Cost / billing controls --------------------------------------------------
# IMPORTANT: with this machine's OAuth (subscription) auth, claude -p draws from
# your plan, not metered API billing. To keep that true and keep rate-limit
# consumption low, the automated steps use cheap models — Opus is reserved for
# your interactive work. The gate itself is plain bash and costs nothing.
#
# If an API key is ever present, run_claude() refuses to run (fail-closed) unless
# you explicitly accept metered billing:
LOOP_ALLOW_API_BILLING="${LOOP_ALLOW_API_BILLING:-0}"
# Model per step (cheap by default). Override per run with env vars.
CLAUDE_IMPL_MODEL="${CLAUDE_IMPL_MODEL:-sonnet}"     # implement / repair / decompose
CLAUDE_REVIEW_MODEL="${CLAUDE_REVIEW_MODEL:-haiku}"  # adversarial review verdict

# --- The claude headless (implement) sandbox ----------------------------------
# The implement step runs as a subprocess on a throwaway branch. It can edit files
# and run the build, but the ALLOWLIST denies it git-merge/push/network mischief.
# The deterministic driver — not this subprocess — owns all merges.
CLAUDE_PERMISSION_MODE="${CLAUDE_PERMISSION_MODE:-acceptEdits}"
CLAUDE_ALLOWED_TOOLS="${CLAUDE_ALLOWED_TOOLS:-Read,Edit,Write,Glob,Grep,Bash(make:*),Bash(go:*),Bash(cargo:*),Bash(buf:*),Bash(gofmt:*),Bash(git status),Bash(git diff:*),Bash(ls:*),Bash(cat:*),Bash(rg:*)}"

# --- Security-sensitive paths (deny-by-default escalation) --------------------
# If ANY changed file matches ANY of these extended-regex patterns, the change is
# ESCALATED to a human regardless of how green it is. Deny-beats-allow, mirroring
# the daemon's own Policy model (ADR-0002). Patterns are matched against the file
# path with `grep -E`. Err toward over-inclusion; a false escalation is cheap.
SECURITY_GLOBS=(
  '^proto/'                 # the contract spine (ADR-0007) — every wire change
  '^docs/adr/'              # architecture decisions — by definition hard to reverse
  '^CLAUDE\.md$'            # the invariants
  '^CONTEXT\.md$'           # the ubiquitous language
  '^Makefile$'              # build integrity
  '^\.github/'              # CI / automation integrity
  '^scripts/dev-loop/'      # the loop must never self-modify its own gate unattended
  # security-relevant code, matched by keyword anywhere in the path so it survives
  # files that do not exist yet:
  '([Pp]olicy)'             # daemon Policy engine (ADR-0002)
  '(exec)'                  # Operation executors / Raw Exec (ADR-0001)
  '(transport|grpc|tonic)'  # the wire (ADR-0005)
  '([Mm]tls|[Tt]ls|cert|_ca_|/ca/|[Cc]rypto)' # mTLS / CA (ADR-0005,0006)
  '(enroll|[Aa]uth|token|secret|cred)'         # enrollment & auth (ADR-0006)
)

# --- Notifications ------------------------------------------------------------
# Where escalations get announced. "gh" comments on the issue/PR (always on).
# Extend lib.sh notify() if you want push/email.
NOTIFY_CHANNEL="${NOTIFY_CHANNEL:-gh}"
