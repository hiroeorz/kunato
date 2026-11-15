#!/usr/bin/env python3
"""Measure existing counters/formatting using the real optimized Kunato crate."""
import argparse
import json
from pathlib import Path
import platform
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    lines = subprocess.check_output([
        "cargo", "run", "--offline", "--release", "--example", "observations_bench", "--", "--counters"
    ], cwd=root, text=True).splitlines()
    result = {
        "method": "single-thread microbenchmark of the real crate, seven warmed runs, nanoseconds per operation",
        "limitations": "No HTTP, SSE transport, TLS, disk, concurrent WAF load, or end-to-end latency measurement.",
        "system": platform.platform(),
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "source_files": ["src/metrics.rs", "src/decoy/metrics.rs", "examples/observations_bench.rs"],
        "timings": {},
    }
    for line in lines:
        fields = line.split()
        if len(fields) == 4:
            result["timings"][fields[0]] = dict(zip(["min_ns", "median_ns", "max_ns"], map(float, fields[1:])))
        else:
            result[fields[0]] = int(fields[1])
    args.output.write_text(json.dumps(result, indent=2) + chr(10))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
