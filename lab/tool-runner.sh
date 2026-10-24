#!/bin/sh
# Keep bounded tmpfs reports available until the controller has collected them.
/app/gotestwaf "$@"
tool_status=$?
printf '%s\n' "$tool_status" > /reports/exit-code
while :; do
    sleep 1
done
