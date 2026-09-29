#!/usr/bin/env bash
# Shared readers for the ADR headers and the amendment links between ADRs. Sourced by
# scripts/check-crosslinks.sh (the gate) and scripts/adr-index.sh (the generator) so the two can
# never disagree about what "amends" means. Bash + grep + awk; no toolchain.
#
# The wording is what gets read, never a hand-kept list. An ADR "amends" ADR-NNNN when its text
# says so in one of the two shapes the ADRs actually use, joined across a wrapped line:
#
#   amends / amended by / supersedes / superseded (in part) (by) … ADR-NNNN [and ADR-MMMM]
#   ADR-NNNN [and ADR-MMMM] is / are amended / superseded
#
# "Amendment" (the noun) is deliberately not a trigger: "see the ADR-0010 amendment of the
# same date" is a cross-reference, not a claim that this ADR amends ADR-0010.

# adr_number <file>  →  NNNN
adr_number() { basename "$1" | cut -c1-4; }

# adr_title <file>  →  the H1 without its "# "
adr_title() { head -1 "$1" | sed -E 's/^# //'; }

# adr_status <file>  →  the text after "**Status:**" in the first paragraph that opens with it,
# its continuation lines joined up to the next blank line (a Status may wrap), with no trailing
# period; or the empty string when the file has no such line.
adr_status() {
  awk '!f && /^\*\*Status:\*\*/ { f=1; s=$0; next }
       f && /^[[:space:]]*$/    { exit }
       f                        { s=s " " $0 }
       END                      { if (f) print s }' "$1" \
    | sed -E 's/^\*\*Status:\*\* *//; s/[[:space:]]+/ /g; s/ $//; s/\.$//'
  return 0
}

# adr_in_force <file>  →  exit 0 unless the Status header says Proposed, Deferred or Withdrawn.
# An ADR that was never adopted amends nothing, so the back-link rule does not bind it.
adr_in_force() {
  case "$(adr_status "$1")" in
    Proposed*|Deferred*|Withdrawn*) return 1 ;;
    *) return 0 ;;
  esac
}

# _adr_paragraphs <file>  →  the file one paragraph per line (blank-line separated, newlines
# joined with spaces), so a phrase wrapped across two lines still reads as one phrase.
_adr_paragraphs() { awk 'BEGIN{RS=""} {gsub(/\n/," "); print}' "$1"; }

_ADR_LIST='ADR-[0-9]{4}(( and|,)( by)? \*{0,2}\[?ADR-[0-9]{4})*'

# adr_amends <file>  →  the numbers of the ADRs this one says it amends or supersedes, one
# per line, sorted and unique, never its own number. Active voice ("amends ADR-0005 and
# ADR-0006") or passive with this ADR as the agent ("ADR-0004 and ADR-0012 are amended").
adr_amends() {
  local self; self=$(adr_number "$1")
  {
    _adr_paragraphs "$1" \
      | grep -oiE "\b(amends|amending|supersedes|superseding)( in part)?[^.;:]{0,60}\*{0,2}\[?${_ADR_LIST}" 2>/dev/null
    _adr_paragraphs "$1" \
      | grep -oiE "\*{0,2}${_ADR_LIST}\*{0,2}[^.;:]{0,40}\b(is|are) (amended|superseded)\b" 2>/dev/null
  } | grep -oE 'ADR-[0-9]{4}' | sed 's/^ADR-//' | grep -vx "$self" | sort -u
  return 0
}

# adr_header_amended_by <file>  →  the numbers the file's own text says amend it — the
# "amended by ADR-NNNN" / "superseded by ADR-NNNN" phrasing, wherever it appears (a header
# blockquote, an amendment section's heading, a struck decision). One per line, sorted.
adr_header_amended_by() {
  local self; self=$(adr_number "$1")
  _adr_paragraphs "$1" \
    | grep -oiE "\b(amended|superseded)( in part)? by (\*{0,2}\[?${_ADR_LIST})" 2>/dev/null \
    | grep -oE 'ADR-[0-9]{4}' | sed 's/^ADR-//' | grep -vx "$self" | sort -u
  return 0
}

# adr_file <NNNN>  →  the path of that ADR, or nothing (exit 1) when no file carries the number.
adr_file() {
  local f
  for f in docs/adr/"$1"-*.md; do [ -f "$f" ] && { echo "$f"; return 0; }; done
  return 1
}
