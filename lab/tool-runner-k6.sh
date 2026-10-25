#!/bin/sh
# The k6 summary goes to /reports; keep the tmpfs mounted until the controller collects it.
k6 run --summary-trend-stats "avg,min,med,max,p(90),p(95),p(99)" --summary-export /reports/k6-summary.json "${K6_SCRIPT:-/lab/load.js}"
tool_status=$?
printf '%s\n' "$tool_status" > /reports/exit-code
while :; do
    sleep 1
done
