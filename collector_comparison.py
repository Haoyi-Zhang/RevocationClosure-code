"""Benign same-information collector comparison on owned local SQLite files.

Positive finite lifetimes, positive uncertainty, duplicate polls/receipts,
bounded clock regression, reopen, hidden descendants, and changed/no-op fault
boundaries. No sockets, external effects, third-party targets, or credentials.
The reference shares validation; the feasible-time and authorization oracles
remain separate checks. All outputs and temporary files stay below --out.
"""
from __future__ import annotations
import argparse
import collections
import copy
import itertools
import json
from pathlib import Path
import platform
import random
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

from capability import Store, grant, receipt, revocation
from collector import ClosureJournal, coverage
from collector_reference import DurableReference
from verifier import verify_decision

ARMS = {'reference': DurableReference, 'optimized': ClosureJournal}
PROFILES = ('receipts', 'expiry', 'mixed')


def feasible_times(history, epsilon):
    reachable = {0}
    for clock in history:
        reachable = {t for t in range(11) if abs(clock-t) <= epsilon
                     and any(previous <= t for previous in reachable)}
    return {t for t in range(11) if any(previous <= t for previous in reachable)}


def decompose():
    counts = collections.Counter()
    for eps in (0, 1, 2):
        histories = [()] + [(c,) for c in range(7)] + list(itertools.product(range(7), repeat=2))
        for history in histories:
            times = feasible_times(history, eps)
            if not times:
                counts['infeasible_histories'] += 1
                continue
            counts['feasible_histories'] += 1
            lower = min(times)
            usable = {d: any(c+eps < d for t in times for c in range(13)
                             if abs(c-t) <= eps) for d in range(7)}
            for d0, d1, mask in itertools.product(range(7), range(7), range(4)):
                ds = [d0, d1, 0, 0, 0]
                expected = all(mask & (1 << i) or not usable[d] for i, d in enumerate(ds))
                state = coverage(ds, mask, lower, eps)
                assert state['closed'] == expected
                counts['finite_cases'] += 1
                counts['closed_cases' if expected else 'open_cases'] += 1
                if not history:
                    continue  # the legacy predicate needs a latest reading
                predicate = lambda bound: all(mask & (1 << i) or d <= bound
                                               for i, d in enumerate(ds))
                latest = history[-1] - eps
                if expected and not predicate(latest):
                    counts['additional_vs_raw_latest'] += 1
                    if predicate(max(0, latest)):
                        counts['nonnegative_floor_only_stage'] += 1
                    elif predicate(max(0, latest, eps)):
                        counts['inert_after_floor_stage'] += 1
                    else:
                        counts['history_after_inert_stage'] += 1
                    if not predicate(max(0, latest)):
                        historical = predicate(lower)
                        inert = predicate(max(0, latest, eps))
                        assert historical or inert
                        counts['both_history_and_inert' if historical and inert
                               else 'history_only' if historical else 'inert_only'] += 1
    assert counts['finite_cases'] == 26852
    assert counts['additional_vs_raw_latest'] == 2627
    assert counts['nonnegative_floor_only_stage'] == 1088
    assert (counts['inert_after_floor_stage'], counts['history_after_inert_stage']) == (1061, 478)
    assert (counts['history_only'], counts['inert_only'], counts['both_history_and_inert']) == (478, 686, 375)
    return dict(counts)


def workload(profile, eps, polls, seed):
    """128 positive-duration ticks, 1 or 8 polls per tick; clocks may regress."""
    rng = random.Random(seed)
    start = 20
    deadlines = ([start+240]*3 + [start+60, start+80] if profile == 'mixed'
                 else [start+60+10*i for i in range(5)])
    root = grant(0, 1, None, 3, [start+400]*5, f'root-{profile}-{seed}')
    target = grant(1, 2, root, 1, deadlines, f'target-{profile}-{seed}')
    child = grant(2, 3, target, 1, deadlines, f'hidden-{profile}-{seed}')
    rev = revocation(target)
    arrivals = ({i: start+8+10*i for i in range(3 if profile == 'mixed' else 5)}
                if profile != 'expiry' else {})
    observations = []
    for tick in range(128):
        actual = start+tick
        available = [receipt(i, rev) for i, at in arrivals.items() if at <= actual]
        for poll in range(polls):
            # First poll establishes this real-time tick; subsequent readings
            # lie in the same sound error interval and often supply no new info.
            clock = actual+eps if poll == 0 else rng.randint(actual-eps, actual+eps)
            clock = max(0, clock)
            batch = list(available)
            if batch and poll % 2:
                batch.append(batch[0])
            observations.append(dict(actual=actual, clock=clock, receipts=batch))
    assert eps > 0 and all(d > start+2*eps for d in deadlines)
    return dict(profile=profile, epsilon=eps, polls_per_tick=polls, seed=seed,
                start=start, duration=127, root=root, target=target, child=child,
                revocation=rev, arrivals=arrivals, observations=observations)


def instrument(journal):
    counts = collections.Counter()
    def record(sql):
        counts[sql.split()[0].lower()] += 1
    journal.db.set_trace_callback(record)
    return counts


def check_workload(fixture, directory):
    journals = {arm: cls(directory / f'{arm}.sqlite', fixture['revocation'], fixture['epsilon'])
                for arm, cls in ARMS.items()}
    stores = [Store(directory / f'gateway-{i}.sqlite', i, fixture['epsilon']) for i in range(5)]
    comparisons = post = reopens = regressions = 0
    first = None
    delivered = False
    previous_clock = None
    try:
        for s in stores:
            s.ingest([fixture['root'], fixture['target']])
        for index, observation in enumerate(fixture['observations']):
            if previous_clock is not None and observation['clock'] < previous_clock:
                regressions += 1
            previous_clock = observation['clock']
            if index and index % 97 == 0:
                for arm, j in journals.items():
                    old = j.status()
                    j.close()
                    journals[arm] = ARMS[arm](directory / f'{arm}.sqlite', fixture['revocation'], fixture['epsilon'])
                    assert journals[arm].status() == old
                reopens += 2
            for r in observation['receipts']:
                # Establish the actual honest gateway exclusion before feeding
                # its deterministic fixture receipt to either collector.
                produced = stores[r['gateway']].ingest([fixture['revocation']])['receipts'][0]
                assert produced == r
            states = [j.observe(observation['clock'], observation['receipts']) for j in journals.values()]
            assert states[0] == states[1]
            comparisons += 1
            # Separately express latest sufficient state as the clock high-water
            # mark and accumulated confirmations, not production coverage().
            high_clock = max(o['clock'] for o in fixture['observations'][:index+1])
            confirmed = {r['gateway'] for r in observation['receipts']}
            expected = all(i in confirmed or d <= fixture['epsilon'] or d <= max(0, high_clock-fixture['epsilon'])
                           for i, d in enumerate(fixture['target']['deadlines']))
            assert states[0]['closed'] == expected
            if first is not None:
                assert states[0]['closed']
            if states[0]['closed'] and first is None:
                first = observation['actual']
            if first is not None and not delivered:
                for i, s in enumerate(stores):
                    s.close()
                    stores[i] = Store(directory / f'gateway-{i}.sqlite', i, fixture['epsilon'])
                    stores[i].ingest([fixture['child']])
                delivered = True
            for s in stores:
                s.set_clock(max(0, observation['actual']-fixture['epsilon']))
                leaf = fixture['child'] if delivered else fixture['target']
                decision = s.authorize(leaf['id'], leaf['subject'], 1, 'svc0', True)
                assert verify_decision(decision)
                if first is not None:
                    assert not decision['allow']
                    post += 1
        assert first is not None and first > fixture['start'] and post > 0
        for db in [j.db for j in journals.values()] + [s.db for s in stores]:
            assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    finally:
        for j in journals.values():
            j.close()
        for s in stores:
            s.close()
    return dict(profile=fixture['profile'], epsilon=fixture['epsilon'], seed=fixture['seed'],
                polls_per_tick=fixture['polls_per_tick'], matched_states=comparisons,
                authorization_comparisons=5*comparisons, postclosure_rejections=post,
                first_closed_actual=first, collector_reopens=reopens, clock_regressions=regressions)


def boundaries(directory):
    target = grant(0, 1, None, 1, [100]*5, 'comparison-boundary')
    rev = revocation(target)
    rejected = 0
    for arm, cls in ARMS.items():
        path = directory / f'boundary-{arm}.sqlite'
        with cls(path, rev, 2) as j:
            j.observe(12, [receipt(0, rev)])
            before = j.status()
            wrong = revocation(grant(0, 1, None, 1, [100]*5, 'other'))
            corrupt = copy.deepcopy(receipt(1, rev)); corrupt['mac'] = '0'*64
            for clock, batch in ((12, [receipt(1, rev), corrupt]),
                                 (12, [receipt(1, wrong)]), (0, []),
                                 (12, [receipt(1, rev)]*11)):
                try:
                    j.observe(clock, batch)
                except ValueError:
                    rejected += 1
                else:
                    raise AssertionError('invalid observation accepted')
                assert j.status() == before
            # A second connection advances durable state; no local cached pair
            # may cause the first to lose that receipt or lower-time bound.
            with cls(path, rev, 2) as other:
                other.observe(15, [receipt(1, rev)])
            assert j.observe(12, [])['receipt_mask'] == 3
            assert j.status()['lower_time'] == 13
        try:
            cls(path, rev, 1)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError('configuration rebound')
    faults = []
    for arm, cls in ARMS.items():
        for changed in (True, False):
            for point in ('before_transaction', 'before_commit', 'after_commit_before_reply'):
                path = directory / f'fault-{arm}-{changed}-{point}.sqlite'
                with cls(path, rev, 2) as j:
                    j.observe(10, [receipt(0, rev)])
                    old = j.status()
                config = dict(path=str(path), arm=arm, revocation=rev, point=point,
                              clock=12 if changed else 10,
                              receipts=[receipt(i, rev) for i in range(5)] if changed else [receipt(0, rev)])
                config_path = directory / 'fault-input.json'
                config_path.write_text(json.dumps(config), encoding='utf-8')
                child = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--fault', str(config_path)],
                                       capture_output=True, text=True, timeout=20)
                assert child.returncode == 70, child.stderr
                with cls(path, rev, 2) as j:
                    got = j.status()
                    assert got['closed'] == (changed and point == 'after_commit_before_reply')
                    if not changed or point != 'after_commit_before_reply':
                        assert got == old
                    assert j.db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                faults.append(dict(arm=arm, changed=changed, point=point, exit=child.returncode,
                                   closed_after_reopen=got['closed'], integrity='ok'))
    return dict(rejected_cases=rejected, fault_cases=faults)


def check(out):
    decomposition = decompose()
    fixtures = [workload(p, e, polls, seed) for p in PROFILES for e in (2, 7, 23)
                for polls in (1, 8) for seed in (17, 29)]
    (out / 'comparison-input.json').write_text(json.dumps(fixtures), encoding='utf-8')
    with tempfile.TemporaryDirectory(dir=out) as td:
        directory = Path(td)
        rows = []
        for i, fixture in enumerate(fixtures):
            local = directory / str(i); local.mkdir()
            rows.append(check_workload(fixture, local))
        boundary = boundaries(directory)
    result = dict(decomposition=decomposition, workloads=rows, boundaries=boundary,
                  summary={key: sum(r[key] for r in rows) for key in
                           ('matched_states', 'authorization_comparisons', 'postclosure_rejections',
                            'collector_reopens', 'clock_regressions')}, mismatches=0,
                  scope='same observations and durable contract; finite local workload, not deployment benefit')
    (out / 'comparison.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in ('workloads', 'boundaries')}, indent=2))


def replay_arm(cls, path, fixture, traced=False):
    with cls(path, fixture['revocation'], fixture['epsilon']) as j:
        j.db.execute('PRAGMA wal_autocheckpoint=0')
        j.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        initial_changes = j.db.total_changes
        counts = instrument(j) if traced else None
        before = time.perf_counter_ns()
        states = [j.observe(o['clock'], o['receipts']) for o in fixture['observations']]
        elapsed = time.perf_counter_ns()-before
        j.db.set_trace_callback(None)
        row_updates = j.db.total_changes-initial_changes
        wal_path = Path(str(path)+'-wal')
        wal_bytes = wal_path.stat().st_size if wal_path.exists() else 0
        page_size = j.db.execute('PRAGMA page_size').fetchone()[0]
        frames = 0 if wal_bytes == 0 else (wal_bytes-32)//(page_size+24)
        final = j.status()
    with cls(path, fixture['revocation'], fixture['epsilon']) as j:
        assert j.status() == final
    return dict(elapsed_ns=elapsed, row_updates=row_updates, sql=dict(counts) if traced else None,
                wal_bytes=wal_bytes, wal_frames=frames), states


def measure(out):
    # Plan is fixed in source before timing: all 12 cases, 7 alternating pairs,
    # one untimed whole-trace warmup per arm, seed 17, 128 ticks per replay.
    cases = []
    with tempfile.TemporaryDirectory(dir=out) as td:
        directory = Path(td)
        for profile, eps, polls in itertools.product(PROFILES, (2, 7), (1, 8)):
            fixture = workload(profile, eps, polls, 17)
            tag = f'{profile}-{eps}-{polls}'
            reference_work, a = replay_arm(DurableReference, directory / f'{tag}-work-ref.sqlite', fixture, True)
            optimized_work, b = replay_arm(ClosureJournal, directory / f'{tag}-work-opt.sqlite', fixture, True)
            assert a == b
            # Tracing is NOT active in the timed pairs.
            for arm, cls in ARMS.items():
                replay_arm(cls, directory / f'{tag}-warm-{arm}.sqlite', fixture)
            pairs = []
            for pair in range(7):
                order = list(ARMS) if pair % 2 == 0 else list(reversed(ARMS))
                measurements = {}; replies = {}
                for arm in order:
                    measurements[arm], replies[arm] = replay_arm(ARMS[arm], directory / f'{tag}-{pair}-{arm}.sqlite', fixture)
                assert replies['reference'] == replies['optimized']
                pairs.append(dict(pair=pair, order=order, measurements=measurements,
                                  reference_over_optimized=measurements['reference']['elapsed_ns']/measurements['optimized']['elapsed_ns']))
            ratios = [p['reference_over_optimized'] for p in pairs]
            cases.append(dict(profile=profile, epsilon=eps, polls_per_tick=polls,
                              observations=len(fixture['observations']), work=dict(reference=reference_work, optimized=optimized_work),
                              median_ratio=statistics.median(ratios), slower_pairs=sum(r < 1 for r in ratios), pairs=pairs))
    result = dict(environment=dict(platform=platform.platform(), python=platform.python_version(), sqlite=sqlite3.sqlite_version,
                                   affinity='not pinned', storage='owned candidate-local SQLite WAL/FULL files'),
                  plan=dict(profiles=list(PROFILES), epsilon=[2, 7], polls_per_tick=[1, 8], seed=17, ticks=128, pairs=7,
                            warmups='one whole trace per arm', automatic_wal_checkpoint=False,
                            timing='observe calls and returned states; excludes initialization, reopen, tracing, RPC, and gateway checks'),
                  cases=cases, scope='descriptive paired local timings, not a latency SLA or reduced durability guarantee')
    (out / 'measurement.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    ratios = [c['median_ratio'] for c in cases]
    print(json.dumps(dict(cases=len(cases), median_ratio_range=[min(ratios), max(ratios)],
                          slower_case_medians=sum(r < 1 for r in ratios),
                          work=[{k: c[k] for k in ('profile', 'epsilon', 'polls_per_tick', 'observations', 'work')} for c in cases]), indent=2))


def main():
    if not __debug__:
        raise RuntimeError('Assertions required; do not use -O')
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path)
    parser.add_argument('--measure', action='store_true')
    parser.add_argument('--fault', type=Path)
    args = parser.parse_args()
    if args.fault:
        config = json.loads(args.fault.read_text(encoding='utf-8'))
        with ARMS[config['arm']](Path(config['path']), config['revocation'], 2) as j:
            j.observe(config['clock'], config['receipts'], config['point'])
        raise AssertionError('fault did not fire')
    if args.out is None:
        parser.error('--out is required')
    args.out.mkdir(parents=True, exist_ok=True)
    destination = args.out / ('measurement.json' if args.measure else 'comparison.json')
    if destination.exists():
        raise ValueError('retain earlier results; choose a fresh output directory')
    (measure if args.measure else check)(args.out)


if __name__ == '__main__':
    main()
