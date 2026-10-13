"""Run finite, disk, capacity and replay experiments within this module."""
from __future__ import annotations

import argparse
import json
import os
import platform
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from fixtures import HERE, owned
from capacity_store import CapacityStore
import finite_study
import directed_tests
import campaign
import verify_outputs
from study_io import save


def host_observation():
    host = dict(system=platform.system(), release=platform.release(),
                machine=platform.machine(), processor=platform.processor(),
                logical_processors=os.cpu_count())
    if sys.platform == 'win32':
        command = 'Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | ConvertTo-Json -Compress'
        try:
            process = subprocess.run(['powershell', '-NoProfile', '-Command', command],
                                     check=True, capture_output=True, text=True, timeout=30)
            host['processor_query'] = json.loads(process.stdout)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            host['processor_query'] = None
            host['query_error'] = type(error).__name__
    elif sys.platform.startswith('linux'):
        try:
            lines = Path('/proc/cpuinfo').read_text(encoding='utf-8').splitlines()
            host['processor_model'] = next((line.split(':', 1)[1].strip() for line in lines
                                            if line.startswith('model name') and ':' in line), None)
        except OSError as error:
            host['processor_model'] = None
            host['query_error'] = type(error).__name__
    return host


def main():
    if not __debug__:
        raise RuntimeError("assertions must be enabled")
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("finite", "directed", "campaign", "verify", "fault"))
    parser.add_argument("--out", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--finite-input", type=Path, default=HERE / 'results/finite')
    parser.add_argument("--directed-input", type=Path, default=HERE / 'results/directed')
    parser.add_argument("--campaign-input", type=Path, default=HERE / 'results/campaign')
    args = parser.parse_args()
    if args.stage == "fault":
        value = json.loads(owned(args.input).read_text(encoding="utf-8"))
        s = CapacityStore(owned(value["path"]), **value["config"])
        s.set_clock(value["clock"])
        reply = s.ingest([value["event"]], failpoint=value["point"])
        print(json.dumps(reply), flush=True)
        raise AssertionError("owned fault point did not execute")
    out = args.out or HERE / 'results' / args.stage
    started = datetime.now(timezone.utc).isoformat()
    if args.stage == 'verify':
        result = verify_outputs.run(out, {'finite': args.finite_input,
                                         'directed': args.directed_input,
                                         'campaign': args.campaign_input})
    else:
        result = {"finite": finite_study.run, "directed": directed_tests.run,
                  "campaign": campaign.run}[args.stage](out)
    timers = {name:dict(implementation=time.get_clock_info(name).implementation,
                        monotonic=time.get_clock_info(name).monotonic,
                        adjustable=time.get_clock_info(name).adjustable,
                        resolution_s=time.get_clock_info(name).resolution) for name in ("perf_counter","process_time","time")}
    save(owned(out)/"runtime.json",dict(stage=args.stage, started_utc=started,
                                     finished_utc=datetime.now(timezone.utc).isoformat(),
                                     python=sys.version,sqlite=sqlite3.sqlite_version,platform=platform.platform(),
                                     clocks=timers,host_observation=host_observation(),
                                     model_clocks="explicit nonnegative integer inputs with bound checked against retained synthetic actual time; no measured synchronization"))
    print(json.dumps({k: v for k, v in result.items() if k not in {"cases", "per_configuration"}}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
