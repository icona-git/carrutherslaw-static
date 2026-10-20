#!/bin/bash
# ICONA scaffold-lineage check (2026-09-14).
#
# WHY: ICONA builds start from a previous client's repo. Three times a stray identifier from that
# lineage reached a shippable file (a robots.txt Sitemap line pointing at the previous client's
# domain, README/Dockerfile headers, two dead BuildTasks). This gate fails the branch if ANY other
# ICONA client's name or domain appears in a file that ships.
#
# Usage:  bash scripts/lineage-check.sh            (exit 0 = clean, 1 = flagged, 2 = could not run)
# Scope:  every tracked file EXCEPT docs/ (internal notes may cite history), vendor/, node_modules/,
#         the composer/npm lock files, binary assets, this script and its denylist. docs/content/ IS
#         scanned: it is the site's copy. Run before opening a PR and before any first staging deploy.
set -uo pipefail
# Works in a git checkout (tracked files) AND in a deployed tree with no .git (Plesk checks out
# without one): the fallback walks the filesystem with the same exclusions.
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then MODE=git; else ROOT=$(cd "$(dirname "$0")/.." && pwd) || exit 2; MODE=walk; fi
cd "$ROOT" || exit 2
LIST="$ROOT/scripts/lineage-denylist.txt"
[ -r "$LIST" ] || { echo "FAIL: missing $LIST"; exit 2; }
RE=$(grep -vE '^\s*(#|$)' "$LIST" | sed 's/[.]/\\./g' | paste -sd'|' -)
[ -n "$RE" ] || { echo "FAIL: empty denylist"; exit 2; }
list_all() {
  if [ "$MODE" = git ]; then git ls-files
  else find . -type f -not -path './.git/*' -not -path './silverstripe-cache/*' -not -path './public/assets/*' \
         -not -path './public/_resources/*' -not -path './.graphql-generated/*' -not -name '.env' | sed 's|^\./||'
  fi
}
FILES=$( { list_all | grep -vE '^(docs/|vendor/|themes/startup-theme/)|/node_modules/|^scripts/lineage-|(^|/)(composer|package(-lock)?)\.(lock|json)$' ; list_all | grep -E '^docs/content/' ; } \
  | grep -viE '\.(png|jpe?g|webp|gif|svg|ico|woff2?|ttf|otf|eot|pdf|zip|gz|mp4|log)$' | sort -u )
N=0; FLAGGED=0
while IFS= read -r f; do
  [ -f "$f" ] || continue; N=$((N+1))
  hits=$(grep -ioE "$RE" "$f" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort -u | paste -sd',' -)
  if [ -n "$hits" ]; then
    FLAGGED=$((FLAGGED+1)); echo "FLAG: $f -> $hits"
    grep -inoE ".{0,40}($RE).{0,40}" "$f" 2>/dev/null | head -3 | sed 's/^/      /'
  fi
done <<< "$FILES"
echo "----"
if [ "$FLAGGED" -gt 0 ]; then
  echo "RESULT: FAIL - $FLAGGED of $N shippable files carry another client's identity. Fix the file; never allowlist it."
  exit 1
fi
echo "RESULT: PASS - $N shippable files ($MODE mode), no other-client identifiers."
exit 0
