#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
scan_root=${1:-$repo_root}
violations=$(mktemp)
files=$(mktemp)
trap 'rm -f "$violations" "$files"' EXIT HUP INT TERM

find "$scan_root" \
  -path '*/.git' -prune -o \
  -path '*/target' -prune -o \
  -type f \( -name '*.java' -o -name 'pom.xml' -o -name '*.proto' \) -print > "$files"

while IFS= read -r file; do
  case "$file" in
    *.java)
      grep -nEi '^[[:space:]]*import[[:space:]]+(static[[:space:]]+)?((samos|stn|ham)(\.|;)|[^;]*\.(samos|stn|ham)(\.|;)|(securityphone\.cell|security2)(\.|;)|[^;]*\.(securityphone\.cell|security2)(\.|;))' "$file" >> "$violations" || true
      ;;
    */pom.xml|pom.xml)
      tr '\n\r\t' '   ' < "$file" \
        | grep -Eio '<(groupId|artifactId)>[[:space:]]*(([^<]*[./_-])?(samos|stn|ham)([./_-][^<]*)?|([^<]*[./_-])?(securityphone[.-]cell|security2)([./_-][^<]*)?)[[:space:]]*</(groupId|artifactId)>' \
        | sed "s#^#$file:#" >> "$violations" || true
      ;;
    *.proto)
      grep -nEi '^[[:space:]]*import[[:space:]]+"([^"[:space:]]*[./_-])?(samos|stn|ham)([./_-]|"|$)|^[[:space:]]*import[[:space:]]+"[^"]*(securityphone[./_-]cell|security2)[^"]*"' "$file" >> "$violations" || true
      ;;
  esac
done < "$files"

if [ -s "$violations" ]; then
  echo "Security Phone AGPL process-boundary violation:" >&2
  cat "$violations" >&2
  exit 1
fi

echo "Security Phone AGPL process-boundary check passed"
