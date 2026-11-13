#!/bin/sh
# Anonymous checks for the protected reference. No credentials and no writes.
set -eu
origin="${THREATSIGHT_PUBLIC_ORIGIN:-https://threatsight.io}"
fail=0
redirect() {
  path="$1"
  headers=$(curl -sS -A 'ThreatSightPublicDemoMonitor/1.0' -D - -o /dev/null --max-time 20 "$origin$path") || { echo "FAIL $path"; fail=1; return; }
  printf '%s' "$headers" | grep -Eq ' 30[2378] ' || { echo "FAIL status $path"; fail=1; return; }
  printf '%s' "$headers" | grep -qi "location: /login?return_to=" || { echo "FAIL location $path"; fail=1; return; }
  echo "ok $path"
}
redirect /
redirect /demo
redirect /threats
redirect /services
redirect /paths
redirect /controls
redirect /actions
redirect /evidence
redirect /briefing
redirect /tour
login=$(curl -fsS -A 'ThreatSightPublicDemoMonitor/1.0' --max-time 20 "$origin/login") || { echo "FAIL login"; exit 1; }
printf '%s' "$login" | grep -Eq "Sign in|Checking sign-in" || { echo "FAIL login-title"; fail=1; }
printf '%s' "$login" | grep -q "Command center" && { echo "FAIL anonymous-navigation"; fail=1; }
printf '%s' "$login" | grep -q "demo-viewer" && { echo "FAIL anonymous-identity"; fail=1; }
code=$(curl -sS -o /tmp/threatsight-anon-body -w '%{http_code}' --max-time 20 -H "X-Role: platform-admin" -H "X-Actor: demo-viewer" -H "X-Workspace-Key: other" "$origin/api/v1/radar/workspace")
test "$code" = "401" || { echo "FAIL identity $code"; fail=1; }
grep -q 'demo-viewer' /tmp/threatsight-anon-body && { echo "FAIL demo-viewer"; fail=1; }
rm -f /tmp/threatsight-anon-body
mutation=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -X POST -H 'content-type: application/json' -d '{"name":"x"}' "$origin/api/v1/systems")
test "$mutation" = "401" || { echo "FAIL mutation $mutation"; fail=1; }
echo "anonymous-protection ok"
exit "$fail"
