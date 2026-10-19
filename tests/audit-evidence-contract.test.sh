#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
contract="$repo_root/contracts/securityphone/contracts/v1/audit.proto"

require_field() {
  pattern=$1
  description=$2

  if ! grep -Eq "$pattern" "$contract"; then
    echo "audit contract is missing $description" >&2
    exit 1
  fi
}

require_field 'bytes[[:space:]]+payload_digest[[:space:]]*=[[:space:]]*7;' 'payload digest field 7'
require_field 'string[[:space:]]+evidence_reference[[:space:]]*=[[:space:]]*8;' 'governed evidence reference field 8'
require_field 'string[[:space:]]+evidence_media_type[[:space:]]*=[[:space:]]*9;' 'evidence media type field 9'
require_field 'uint64[[:space:]]+evidence_size_bytes[[:space:]]*=[[:space:]]*10;' 'evidence size field 10'

echo "Security Phone audit evidence contract test passed"
