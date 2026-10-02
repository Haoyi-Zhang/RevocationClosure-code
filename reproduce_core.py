"""Sequential complete reproduction with source-closed resumable chunks.

Linux/Python standard library only. All network traffic goes to owned loopback
servers. A fresh output directory is mandatory unless resuming a saved run.
Every command in one reproduction executes from a retained byte-for-byte source
snapshot; source edits therefore require a new output directory. Do not run
with Python's -O option.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

SEEDS = (101, 211, 307, 401, 503, 601, 701, 809)
# Instrumentation varies between runs; scientific state/decisions must not.
VOLATILE = {
    'wire_bytes', 'reply_wire_bytes', 'wall_s', 'parent_cpu_s', 'children_cpu_s', 'server_cpu_s',
    'server_peak_rss_kib', 'parent_peak_rss_kib', 'service_ns', 'rpc_ns',
    'allocated_sqlite_bytes', 'sqlite_bytes', 'rpc_median_us', 'rpc_p95_us',
    'rpc_p99_us', 'service_median_us', 'service_p95_us', 'service_p99_us',
    'verifier_median_us', 'verifier_p95_us', 'verifier_p99_us',
    'retained_source_files', # separately checked against the executed byte-exact snapshot
}


def semantic(value):
    if isinstance(value, dict):
        return {k: semantic(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [semantic(v) for v in value]
    return value


def source_files(root: Path) -> list[Path]:
    """Return the complete executable Python source set relative to *root*."""
    files = list(root.glob('*.py')) + list((root / 'tests').glob('*.py'))
    return sorted((p.relative_to(root) for p in files), key=lambda p: p.as_posix())


def prepare_source_snapshot(root: Path, out: Path, resume: bool) -> tuple[Path, int]:
    """Create or verify the immutable source snapshot for one reproduction."""
    snapshot = out / 'source'
    current = source_files(root)
    if not current:
        raise ValueError('no executable source files found')
    if resume:
        if not snapshot.is_dir():
            raise ValueError('resume requires the retained source snapshot')
        retained = source_files(snapshot)
        if retained != current:
            raise ValueError('source file set changed; use a fresh output directory')
        for rel in current:
            if (root / rel).read_bytes() != (snapshot / rel).read_bytes():
                raise ValueError(
                    f'source changed since this reproduction began: {rel}; '
                    'use a fresh output directory'
                )
    else:
        if snapshot.exists():
            raise ValueError('fresh output unexpectedly contains a source snapshot')
        for rel in current:
            destination = snapshot / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / rel, destination)
    return snapshot, len(current)


def state_payload(state, reports, segments, failures, source_count):
    return {
        'state': state,
        'commands_executed_from_retained_source_snapshot': True,
        'retained_source_files': source_count,
        'commands': reports,
        'segments': segments,
        'failed_attempts': failures,
    }


def main():
    if not __debug__:
        raise RuntimeError('Assertions are part of the finite checks; do not use -O.')
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=Path('reproduced'))
    parser.add_argument('--compare', type=Path, default=Path('results'))
    parser.add_argument('--resume', action='store_true')
    parser.add_argument(
        '--retry-failed', action='store_true',
        help='rerun only the final transient failure under the unchanged retained source snapshot',
    )
    parser.add_argument(
        '--max-commands', type=int, default=0,
        help='zero runs all remaining commands; positive values produce bounded resumable chunks',
    )
    args = parser.parse_args()
    if args.max_commands < 0:
        raise ValueError('negative chunk limit')

    root = Path(__file__).resolve().parent
    out = args.out.resolve()
    reference = args.compare.resolve()
    if out == reference:
        raise ValueError('output must differ from retained results')
    if out.exists() and any(out.iterdir()) and not args.resume:
        raise ValueError('nonempty output requires --resume')
    if args.resume and not (out / 'reproduction.json').is_file():
        raise ValueError('resume requires a saved reproduction state')
    if not reference.is_dir():
        raise ValueError('reference results directory missing')

    out.mkdir(parents=True, exist_ok=True)
    source_root, source_count = prepare_source_snapshot(root, out, args.resume)
    logs = out / 'commands'
    logs.mkdir(exist_ok=True)

    commands = [
        ['pilot.py'], ['finite.py'], ['crashes.py'], ['policies.py'],
        ['tests/boundaries.py'], ['tests/recovery_compaction_window.py'],
        ['tests/differential_audit.py'], ['tests/closure_descendants.py'],
        ['tests/reproduction_guard.py'],
    ]
    commands += [['histories.py', '--seed', str(seed)] for seed in SEEDS]
    commands += [
        ['benchmark.py', '--records', str(records), '--depth', str(depth), '--seed', str(seed)]
        for records in (100, 1000, 5000, 10000)
        for depth in (1, 4, 16, 64)
        for seed in (17, 29, 43)
    ]
    commands = [command + ['--out', str(out)] for command in commands]
    commands += [
        ['verify_history.py', '--directory', str(out)],
        ['summarize.py', '--directory', str(out)],
        ['tests/clock_bounds.py', '--out', str(out)],
        ['tests/clock_regression.py', '--out', str(out)],
        ['tests/collector_audit.py', '--out', str(out)],
        ['tests/collector_stateful.py', '--out', str(out)],
    ]

    saved = json.loads((out / 'reproduction.json').read_text()) if args.resume else {}
    reports = saved.get('commands', [])
    segments = saved.get('segments', [])
    failures = saved.get('failed_attempts', [])
    if args.resume:
        if not saved.get('commands_executed_from_retained_source_snapshot'):
            raise ValueError('saved state predates source-closed reproduction; use a fresh output')
        if saved.get('retained_source_files') != source_count:
            raise ValueError('saved source count differs from retained snapshot')

    if any(report['exit_code'] != 0 for report in reports):
        final_only = reports[-1]['exit_code'] != 0 and all(
            report['exit_code'] == 0 for report in reports[:-1]
        )
        if not args.retry_failed or not final_only:
            raise ValueError(
                'a final failed command needs --resume --retry-failed under unchanged source; '
                'a source repair requires a fresh output directory'
            )
        old = reports.pop()
        index = len(reports) + 1
        old_log = logs / f'command-{index:02d}.log'
        retained_log = logs / f'command-{index:02d}-failed-{len(failures) + 1}.log'
        if old_log.exists():
            old_log.replace(retained_log)
        failures.append({
            'report': old,
            'log': retained_log.name,
            'repair_note': 'Explicit transient retry under the unchanged retained source snapshot.',
        })

    completed = len(reports)
    if completed > len(commands):
        raise ValueError('invalid saved command count')
    for index, report in enumerate(reports):
        expected = [str(item).replace(str(out), '<output>') for item in commands[index]]
        if report['command'][1:] != expected:
            raise ValueError('saved command order does not match current schedule')

    segment_start = time.perf_counter()
    parent_start = time.process_time()
    this_segment = 0
    for index, command_args in enumerate(commands):
        if index < completed:
            continue
        if args.max_commands and this_segment >= args.max_commands:
            break
        command = [sys.executable, *command_args]
        began = time.perf_counter()
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        # Logs carry command-local observations, not a toolchain fingerprint.
        with (logs / f'command-{index + 1:02d}.log').open('w') as stream:
            process = subprocess.Popen(
                command,
                cwd=source_root,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
            )
            try:
                code = process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                code = 124
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        report = {
            'command': [
                sys.executable,
                *[str(item).replace(str(out), '<output>') for item in command_args],
            ],
            'exit_code': code,
            'wall_s': time.perf_counter() - began,
            'children_cpu_s': (
                after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime
            ),
        }
        reports.append(report)
        this_segment += 1
        payload = state_payload(
            'running' if code == 0 else 'failed', reports, segments, failures, source_count
        )
        (out / 'reproduction.json').write_text(json.dumps(payload, indent=2) + '\n')
        print(f'{index + 1}/{len(commands)} {command_args[0]} exit={code}', flush=True)
        if code:
            raise RuntimeError(f'command failed; see {logs}')

    segments.append({
        'wall_s': time.perf_counter() - segment_start,
        'coordinator_cpu_s': time.process_time() - parent_start,
        'completed_commands': this_segment,
    })
    if len(reports) < len(commands):
        payload = state_payload('paused', reports, segments, failures, source_count)
        (out / 'reproduction.json').write_text(json.dumps(payload, indent=2) + '\n')
        print('Paused at a command boundary; continue with --resume.', flush=True)
        return

    names = [
        'pilot.json', 'finite.json', 'crashes.json', 'policies.json',
        'boundaries.json', 'recovery-compaction-window.json',
        'differential-audit.json', 'closure-descendants.json',
        'reproduction-guard.json',
        'clock-bounds.json', 'clock-regression.json',
        'collector-audit.json', 'collector-stateful.json',
    ]
    names += [f'history-{seed}.json' for seed in SEEDS]
    names += [
        f'scale-{records}-{depth}-{seed}.json'
        for records in (100, 1000, 5000, 10000)
        for depth in (1, 4, 16, 64)
        for seed in (17, 29, 43)
    ]
    compared = []
    for name in names:
        current = json.loads((out / name).read_text())
        prior = json.loads((reference / name).read_text())
        if semantic(current) != semantic(prior):
            raise AssertionError('semantic result differs: ' + name)
        compared.append(name)

    # Compare exact consumed structured inputs, not gzip header timestamps.
    reference_fixtures = sorted(path.name for path in reference.glob('*-input.json.gz'))
    current_fixtures = sorted(path.name for path in out.glob('*-input.json.gz'))
    if current_fixtures != reference_fixtures:
        raise AssertionError('structured input fixture set differs')
    for name in reference_fixtures:
        with gzip.open(reference / name, 'rt') as left, gzip.open(out / name, 'rt') as right:
            if json.load(left) != json.load(right):
                raise AssertionError('structured input differs: ' + name)

    for name in ['collector-stateful-trace.jsonl.gz']:
        with gzip.open(reference / name, 'rb') as a, gzip.open(out / name, 'rb') as b:
            if a.read() != b.read():
                raise AssertionError('collector state trace differs: ' + name)
    result = state_payload('complete', reports, segments, failures, source_count)
    result.update({
        'semantic_comparisons': len(compared),
        'exact_structured_inputs_compared': len(reference_fixtures),
        'timing_equality_required': False,
        'completed_segment_wall_s': sum(segment['wall_s'] for segment in segments),
        'coordinator_cpu_s': sum(segment['coordinator_cpu_s'] for segment in segments),
        'command_children_cpu_s': sum(report['children_cpu_s'] for report in reports),
        'coordinator_peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'boundary': (
            'Successful finite checks and exact fixture/semantic replay are not a proof '
            'of general correctness or an independent scientific review.'
        ),
    })
    (out / 'reproduction.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'commands'}, indent=2))


if __name__ == '__main__':
    main()
