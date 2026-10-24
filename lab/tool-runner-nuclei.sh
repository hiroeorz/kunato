#!/bin/sh
# Keep the bounded tmpfs reports available until the controller collects them.
mkdir -p /tmp/nuclei-templates
/usr/local/bin/nuclei "$@"
tool_status=$?
printf '%s\n' "$tool_status" > /reports/exit-code
while :; do
    sleep 1
done
