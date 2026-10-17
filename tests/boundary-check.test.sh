#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT HUP INT TERM

mkdir -p "$fixture_root/service/src/main/java/example" "$fixture_root/contracts"
cat > "$fixture_root/service/src/main/java/example/BoundaryViolation.java" <<'EOF'
package example;
import org.samos.Anything;
final class BoundaryViolation {}
EOF

if "$repo_root/scripts/boundary-check.sh" "$fixture_root" >/dev/null 2>&1; then
  echo "boundary-check accepted a forbidden Java import" >&2
  exit 1
fi

rm "$fixture_root/service/src/main/java/example/BoundaryViolation.java"
cat > "$fixture_root/service/src/main/java/example/TopLevelBoundaryViolation.java" <<'EOF'
package example;
import stn.Client;
final class TopLevelBoundaryViolation {}
EOF

if "$repo_root/scripts/boundary-check.sh" "$fixture_root" >/dev/null 2>&1; then
  echo "boundary-check accepted a forbidden top-level Java import" >&2
  exit 1
fi

rm "$fixture_root/service/src/main/java/example/TopLevelBoundaryViolation.java"
cat > "$fixture_root/pom.xml" <<'EOF'
<project><dependencies><dependency><groupId>org.stn.private</groupId><artifactId>policy-client</artifactId></dependency></dependencies></project>
EOF
if "$repo_root/scripts/boundary-check.sh" "$fixture_root" >/dev/null 2>&1; then
  echo "boundary-check accepted a forbidden Maven dependency" >&2
  exit 1
fi
rm "$fixture_root/pom.xml"

cat > "$fixture_root/pom.xml" <<'EOF'
<project>
  <dependencies>
    <dependency>
      <groupId>
        org.stn.private
      </groupId>
      <artifactId>policy-client</artifactId>
    </dependency>
  </dependencies>
</project>
EOF
if "$repo_root/scripts/boundary-check.sh" "$fixture_root" >/dev/null 2>&1; then
  echo "boundary-check accepted a forbidden multiline Maven dependency" >&2
  exit 1
fi
rm "$fixture_root/pom.xml"

cat > "$fixture_root/contracts/violation.proto" <<'EOF'
syntax = "proto3";
package example;
import "samos/private/policy.proto";
message Violation {}
EOF
if "$repo_root/scripts/boundary-check.sh" "$fixture_root" >/dev/null 2>&1; then
  echo "boundary-check accepted a forbidden protocol import" >&2
  exit 1
fi
rm "$fixture_root/contracts/violation.proto"

cat > "$fixture_root/service/src/main/java/example/Allowed.java" <<'EOF'
package example;
import java.time.Instant;
final class Allowed { Instant now; }
EOF
cat > "$fixture_root/contracts/allowed.proto" <<'EOF'
syntax = "proto3";
package securityphone.contracts.v1;
import "google/protobuf/timestamp.proto";
message Allowed { google.protobuf.Timestamp created_at = 1; }
EOF

"$repo_root/scripts/boundary-check.sh" "$fixture_root"
echo "Security Phone AGPL process-boundary acceptance test passed"
