#!/usr/bin/env bash
# Documentation cross-links, machine-checked instead of read-for-drift. Runs from `make docs-check`
# after scripts/check-docs.sh. Bash + grep + awk; `gh` only for the milestone check, and only when
# present. Every finding names file:line where one exists.
#
# FAIL (exit 1):
#   1. Every `ADR-NNNN` cited in docs/, AGENTS.md, GLOSSARY.md, README.md, relay/ and daemon/
#      (generated *.pb.go and target/ excluded) resolves to docs/adr/NNNN-*.md. No phantoms.
#   3. Amendment back-links: when an ADR in force says it amends or supersedes ADR-NNNN, ADR NNNN
#      mentions the amending ADR by number. An ADR whose Status is Proposed or Deferred amends
#      nothing, so it is not held to this.
#   4. The invariant→boundary map in docs/security/threat-model.md has a row for every invariant
#      #1–#14 (the count is fixed by AGENTS.md: "never renumber or drop one").
#   5. Every milestone a spec's "Designed, not built" table names exists on GitHub — via `gh api`
#      when gh is available and authenticated; otherwise SKIPPED, and reported as skipped.
#   9. docs/adr/README.md is exactly what scripts/adr-index.sh generates (drift gate).
#  10. Every ADR carries a `**Status:**` line as the first line after its title.
#
# WARN (reported, exit unaffected):
#   2. Every ADR is cited at least once outside docs/adr/ (orphans).
#   6. GLOSSARY `_Avoid_` sweep: each rejected term, as a whole word, case-insensitive, across
#      docs/specs/, AGENTS.md, README.md and GLOSSARY.md (its own `_Avoid_` lines excluded).
#      docs/agents/avoid-allowlist.txt lists the accepted hits: `term` allows it everywhere,
#      `term @ <path-glob>` in matching files only.
#   7. A migrated spec (Status current/designed) names no file path (`relay/`, `daemon/`, `.go`,
#      `.rs`, `.proto`) and has no code fence, except a fence introduced by a line that says
#      "state machine" or "schema" — the TEMPLATE's one exception.
#   8. Prose lines over 100 characters in a migrated spec, table rows and fenced blocks excluded.
#
# The amendment vocabulary the checks read is in scripts/adr-links.sh, shared with the generator.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=scripts/adr-links.sh
source scripts/adr-links.sh

fail=0; warned=0; skipped=0
err()  { echo "check-crosslinks: FAIL $*" >&2; fail=1; }
warn() { echo "check-crosslinks: warn $*" >&2; warned=$((warned + 1)); }
# Under `make verify`, a skip is also appended to its skip ledger, so verify's last line reports it.
skip() {
  echo "check-crosslinks: SKIP $*" >&2; skipped=$((skipped + 1))
  if [ -n "${RELAY_VERIFY_SKIPS:-}" ]; then echo "check-crosslinks: $*" >> "$RELAY_VERIFY_SKIPS"; fi
}

# Where ADR citations are looked for. docs/adr/ itself is included for the phantom check and
# excluded (--exclude-dir=adr) for the orphan check.
CITING=(docs AGENTS.md GLOSSARY.md README.md relay daemon)
cite_grep() { grep -rnoIE "$@" "${CITING[@]}" --exclude='*.pb.go' --exclude-dir=target 2>/dev/null; }

# Print the body of one "## Heading" section (up to the next "## ").
section() { awk -v h="## $2" '$0==h{f=1;next} /^## /{f=0} f' "$1"; }

# ---- 1. phantom ADR citations ---------------------------------------------------------------
while IFS=: read -r file line adr; do
  [ -n "${adr:-}" ] || continue
  n=${adr#ADR-}
  adr_file "$n" >/dev/null || err "$file:$line: cites $adr, but no docs/adr/$n-*.md exists (phantom citation)"
done < <(cite_grep 'ADR-[0-9]{4}' | sort -u)

# ---- 2. orphan ADRs (warning) ---------------------------------------------------------------
# One pass over the tree: every number cited as ADR-NNNN or linked as NNNN-<slug>.md outside docs/adr/.
cited_outside=$(grep -rhoIE 'ADR-[0-9]{4}\b|/[0-9]{4}-[a-z0-9-]+\.md' "${CITING[@]}" \
                  --exclude='*.pb.go' --exclude-dir=target --exclude-dir=adr 2>/dev/null \
                | grep -oE '[0-9]{4}' | sort -u)
for f in docs/adr/[0-9]*.md; do
  n=$(adr_number "$f")
  grep -qx "$n" <<<"$cited_outside" \
    || warn "$f: ADR-$n is cited nowhere outside docs/adr/ (orphan)"
done

# ---- 10. every ADR has a Status header (checked before 3, which reads it) -------------------
for f in docs/adr/[0-9]*.md; do
  awk 'NR==3' "$f" | grep -qE '^\*\*Status:\*\* \S' \
    || err "$f:3: no \`**Status:** …\` line as the first line after the title"
done

# ---- 3. amendment back-links ----------------------------------------------------------------
for f in docs/adr/[0-9]*.md; do
  y=$(adr_number "$f")
  adr_in_force "$f" || continue
  for x in $(adr_amends "$f"); do
    xf=$(adr_file "$x") || { err "$f: says it amends or supersedes ADR-$x, which does not exist"; continue; }
    grep -qE "ADR-$y\b" "$xf" \
      || err "$xf: ADR-$y says it amends or supersedes this ADR, and this file never mentions ADR-$y (missing back-link; add a dated amendment note)"
  done
  for x in $(adr_header_amended_by "$f"); do
    adr_file "$x" >/dev/null || err "$f: says it is amended by ADR-$x, which does not exist"
  done
done

# ---- 4. the threat model maps every invariant -----------------------------------------------
tm=docs/security/threat-model.md
if [ -f "$tm" ]; then
  for i in $(seq 1 14); do
    grep -qE "^\| *#$i —" "$tm" || err "$tm: the invariant→boundary map has no row \`| #$i —\` for invariant $i"
  done
  for i in $(grep -oE '^\| *#[0-9]+ —' "$tm" | grep -oE '[0-9]+'); do
    [ "$i" -le 14 ] || err "$tm: the invariant→boundary map has a row for #$i, and AGENTS.md defines fourteen invariants"
  done
else
  err "$tm is missing"
fi

# ---- 5. Designed-claim milestones exist on GitHub ---------------------------------------------
needed=$(for s in docs/specs/*.md; do
  case "$s" in */README.md|*/TEMPLATE.md) continue;; esac
  section "$s" "Designed, not built" | grep -E '^\|' | grep -vE '^\| *(Claim|-)' \
    | awk -F'|' -v s="$s" '{gsub(/^ +| +$/,"",$4); if ($4!="") print s "\t" $4}'
done | sort -u)
if [ -n "$needed" ]; then
  repo=${RELAY_GH_REPO:-Felag-Engineering/gleipnir-relay}
  if ! command -v gh >/dev/null 2>&1; then
    skip "milestone check: gh is not installed, so the milestones named by Designed claims were NOT verified against GitHub"
  elif ! titles=$(gh api "repos/$repo/milestones?state=all&per_page=100" --paginate -q '.[].title' 2>/dev/null) || [ -z "$titles" ]; then
    skip "milestone check: gh api could not list $repo milestones (unauthenticated or offline), so they were NOT verified"
  else
    while IFS=$'\t' read -r spec title; do
      grep -qxF -- "$title" <<<"$titles" \
        || err "$spec: Designed, not built names milestone \"$title\", which is not a milestone on $repo"
    done <<< "$needed"
  fi
fi

# ---- 6. GLOSSARY _Avoid_ sweep (warning) ----------------------------------------------------
allow=docs/agents/avoid-allowlist.txt
allow_terms=(); allow_globs=()                 # parsed once: comments and blanks dropped, trimmed
if [ -f "$allow" ]; then
  while IFS=$'\t' read -r term glob; do
    allow_terms+=("${term,,}"); allow_globs+=("${glob:-*}")
  done < <(sed -E 's/#.*//; s/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d; s/[[:space:]]+@[[:space:]]+/\t/' "$allow")
fi
allowed() {                                    # allowed <term> <file>
  local t=${1,,} f=$2 i
  for i in "${!allow_terms[@]}"; do
    [ "${allow_terms[$i]}" = '*' ] || [ "${allow_terms[$i]}" = "$t" ] || continue
    # shellcheck disable=SC2053
    [[ $f == ${allow_globs[$i]} ]] && return 0
  done
  return 1
}
if [ -f GLOSSARY.md ]; then
  tmpd=$(mktemp -d); trap 'rm -rf "$tmpd"' EXIT
  # Each _Avoid_ block joined onto one line: "start<TAB>end<TAB>text". A block runs from the
  # `_Avoid_:` line to the next blank line or the next line that opens something else.
  awk '
    /^_Avoid_:/ { if (inb) print s "\t" e "\t" txt; inb=1; s=NR; e=NR; txt=$0; next }
    inb && ($0=="" || $0 ~ /^(_|#|\*\*|\||-|>)/) { print s "\t" e "\t" txt; inb=0; next }
    inb { e=NR; txt=txt " " $0 }
    END { if (inb) print s "\t" e "\t" txt }' GLOSSARY.md > "$tmpd/blocks"
  # GLOSSARY.md with its own _Avoid_ blocks blanked, line numbers preserved.
  awk -v blocks="$tmpd/blocks" '
    BEGIN { while ((getline l < blocks) > 0) { split(l, a, "\t"); for (i=a[1]; i<=a[2]; i++) skip[i]=1 } }
    { print (NR in skip) ? "" : $0 }' GLOSSARY.md > "$tmpd/GLOSSARY.md"
  # The rejected terms: parentheticals stripped, split on , and ;, quotes and emphasis removed,
  # a quoted lead ("task" unqualified …) reduced to the quoted word, kept only when short and
  # plain — a clause is commentary, not a term. A term that is also a glossary headword
  # (`**Policy**:`, `**Task**:`) is rejected only in a sense its qualifier names ("policy —
  # reserved for the Node-side document"); a whole-word grep cannot tell the senses apart, so
  # headwords are not swept.
  grep -oE '^\*\*[^*]+\*\*:' GLOSSARY.md | tr -d '*:' | tr 'A-Z' 'a-z' | sort -u > "$tmpd/headwords"
  cut -f3 "$tmpd/blocks" | sed -E 's/^_Avoid_: *//; s/\([^)]*\)//g' | tr ',;' '\n\n' \
    | sed -E 's/^ +| +$//g; s/^"([^"]+)".*/\1/; s/[*`"]//g; s/^ +| +$//g' \
    | grep -E '^[A-Za-z][A-Za-z0-9 -]*$' | awk 'NF>=1 && NF<=3' | tr 'A-Z' 'a-z' | sort -u \
    | grep -vxFf "$tmpd/headwords" > "$tmpd/terms"
  sweep=(docs/specs/*.md AGENTS.md README.md "$tmpd/GLOSSARY.md")
  # Whole word, case-insensitive, and a hyphen is NOT a boundary: "AI-agent", "relay-daemon"
  # and "step-up" are canonical compounds, not hits on "ai", "agent" or "step".
  while IFS= read -r term; do
    [ -n "$term" ] || continue
    re="(^|[^[:alnum:]_-])$(printf '%s' "$term" | sed -E 's/[][\\.^$*+?(){}|]/\\&/g')([^[:alnum:]_-]|$)"
    grep -niE -- "$re" "${sweep[@]}" 2>/dev/null | awk -F: -v t="$term" '
      { f=$1; sub(/^.*\/GLOSSARY\.md$/, "GLOSSARY.md", f); if (!(f in first)) { first[f]=$2; order[++n]=f } cnt[f]++ }
      END { for (i=1;i<=n;i++) printf "%s\t%s\t%d\t%s\n", order[i], first[order[i]], cnt[order[i]], t }'
  done < "$tmpd/terms" > "$tmpd/hits"
  while IFS=$'\t' read -r file line count term; do
    allowed "$term" "$file" && continue
    warn "$file:$line: \"$term\" is on a GLOSSARY _Avoid_ line ($count hit(s) in this file; see $allow)"
  done < "$tmpd/hits"
fi

# ---- 7 & 8. migrated specs: no file paths or fences; prose width ------------------------------
for spec in docs/specs/*.md; do
  case "$spec" in */README.md|*/TEMPLATE.md) continue;; esac
  status=$(grep -m1 -E '^\*\*Status:\*\*' "$spec" | sed -E 's/^\*\*Status:\*\* *//')
  case "$status" in "current as of "*|"designed, not built, as of "*) ;; *) continue ;; esac
  # 7a. path-shaped tokens; `gleipnir-relay/…` (the repo URL) is not a path into relay/.
  while IFS=: read -r line _; do
    warn "$spec:$line: names a file path or source file (relay/, daemon/, .go, .rs, .proto); specs name modules and contracts"
  done < <(grep -nE '(^|[^A-Za-z0-9_-])(relay|daemon)/|\.(go|rs|proto)\b' "$spec")
  # 7b. code fences, unless introduced by "state machine" or "schema" within the three lines above.
  while read -r line; do
    warn "$spec:$line: code fence in a migrated spec (allowed only for a state machine or a schema, said on the line above)"
  done < <(awk '
    /^ *```/ { if (!open) { ok=0; for (i=NR-1; i>=NR-3 && i>=1; i--) if (tolower(prev[i]) ~ /state machine|schema/) ok=1;
                            if (!ok) print NR }
               open=!open }
    { prev[NR]=$0 }' "$spec")
  # 8. prose width
  while IFS=: read -r line len; do
    warn "$spec:$line: prose line is $len characters (limit 100; table rows exempt)"
  done < <(awk '
    /^ *```/ { open=!open; next }
    !open && $0 !~ /^\|/ && length($0) > 100 { print NR ":" length($0) }' "$spec")
done

# ---- 9. the ADR index is generated, not hand-kept --------------------------------------------
if [ -f docs/adr/README.md ]; then
  if ! diff -q <(scripts/adr-index.sh) docs/adr/README.md >/dev/null 2>&1; then
    err "docs/adr/README.md differs from what scripts/adr-index.sh generates — run \`make adr-index\` and commit"
  fi
else
  err "docs/adr/README.md is missing — run \`make adr-index\` and commit"
fi

summary="$warned warning(s), $skipped check(s) skipped"
if [ "$fail" -eq 0 ]; then
  echo "check-crosslinks: ADR citations resolve; amendment back-links present; threat model maps all 14 invariants; ADR index current ($summary)."
else
  echo "check-crosslinks: FAILED ($summary)." >&2
fi
exit "$fail"
