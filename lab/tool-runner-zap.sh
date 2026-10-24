#!/bin/sh
# Keep the bounded tmpfs reports available until the controller collects them.
/zap/zap.sh -Xmx3072m -cmd -silent -autorun "$1"
tool_status=$?
if [ -s /reports/zap.json ]; then
    tool_status=0
fi
printf '%s\n' "$tool_status" > /reports/exit-code
while :; do
    sleep 1
done
