"""Owned local SQL lookup comparison; no sockets, faults, or remote targets."""
from __future__ import annotations
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import random
import sqlite3
import statistics
import time

from capability import Store, grant, revocation
from verifier import Replay


class SequentialStore(Store):
    """Matched comparator: change only revocation lookup, not authorization."""
    def _first_revoked(self, consider):
        if self.mode == 'lease':
            return None
        for g in consider:
            row = self.db.execute("SELECT id,stamp FROM events WHERE kind='revoke' AND target=? ORDER BY id LIMIT 1",(g['id'],)).fetchone()
            revoked = row is not None or g['id'] in self.volatile
            if self.mode == 'lww' and row is not None:
                stamp = self.db.execute('SELECT stamp FROM events WHERE id=?',(g['id'],)).fetchone()[0]
                revoked = row[1] >= stamp
            if revoked:
                return g['id']
        return None


def chain(depth, tag):
    parent = None
    records = []
    for j in range(depth):
        issuer = 0 if parent is None else parent['subject']
        parent = grant(issuer,(issuer+1)%5,parent,7,[10000]*5,tag+'-'+str(j))
        records.append(parent)
    return records


def check():
    decisions = oracle_decisions = 0
    modes = ('closed','all-ack','lease','lww','acl','volatile','no-floor','leaf-only','clock-unsafe')
    for depth in (1,2,4,16,64,256):
        records = chain(depth,'correctness')
        leaf = records[-1]
        for mode in modes:
            for revoked_index in (None,0,depth//2,depth-1):
                a,b=Store(Path(':memory:'),0,epsilon=2,mode=mode),SequentialStore(Path(':memory:'),0,epsilon=2,mode=mode)
                try:
                    fixture=list(records)
                    if revoked_index is not None:
                        fixture.append(revocation(records[revoked_index]))
                    for store in (a,b):
                        store.set_clock(10)
                        store.ingest(fixture)
                    replay=Replay(0,2)
                    replay.ingest(a.events())
                    for clock in (11,9998,10000):
                        for actor in (leaf['subject'],(leaf['subject']+1)%5):
                            for right in (1,7,8):
                                for store in (a,b):
                                    store.set_clock(clock)
                                args=(leaf['id'],actor,right,leaf['service'])
                                left,right_decision=a.authorize(*args),b.authorize(*args)
                                assert left == right_decision
                                decisions+=1
                                if mode == 'closed':
                                    request=dict(cap=leaf['id'],actor=actor,right=right,service=leaf['service'])
                                    assert replay.decide(request,clock)==(left['reason'],left['atom'])
                                    oracle_decisions+=1
                    # Compaction and stale replay preserve both decisions and
                    # the durable floor; no cross-request cache is installed.
                    for store in (a,b):
                        store.set_clock(10002)
                        store.compact()
                        store.ingest(fixture)
                    assert a.events()==b.events()
                    assert a.authorize(leaf['id'],leaf['subject'],1,leaf['service'])==b.authorize(leaf['id'],leaf['subject'],1,leaf['service'])
                    decisions+=1
                finally:
                    a.close();b.close()
    return dict(matched_decisions=decisions,independent_oracle_decisions=oracle_decisions,
                modes=list(modes),depths=[1,2,4,16,64,256],passed=True)


def pin():
    if os.name == 'nt':
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.GetCurrentProcess.restype=ctypes.c_void_p
        kernel.GetProcessAffinityMask.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.POINTER(ctypes.c_size_t)]
        kernel.SetProcessAffinityMask.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
        process=kernel.GetCurrentProcess()
        allowed,system=ctypes.c_size_t(),ctypes.c_size_t()
        if not kernel.GetProcessAffinityMask(process,ctypes.byref(allowed),ctypes.byref(system)):
            raise OSError(ctypes.get_last_error())
        chosen=allowed.value & -allowed.value
        if not kernel.SetProcessAffinityMask(process,chosen):
            raise OSError(ctypes.get_last_error())
        actual=ctypes.c_size_t()
        assert kernel.GetProcessAffinityMask(process,ctypes.byref(actual),ctypes.byref(system)) and actual.value==chosen
        return dict(original_mask=hex(allowed.value),actual_mask=hex(actual.value))
    allowed=os.sched_getaffinity(0)
    cpu=min(allowed)
    os.sched_setaffinity(0,{cpu})
    assert os.sched_getaffinity(0)=={cpu}
    return dict(original_cpus=sorted(allowed),actual_cpu=cpu)


def measure():
    affinity=pin()
    results=[]
    for records_count in (100,1000,10000):
        for depth in (1,4,16,64):
            records=chain(depth,'measurement')
            leaf=records[-1]
            records += [grant(j%5,(j+1)%5,None,7,[10000]*5,'filler-'+str(j)) for j in range(depth,records_count)]
            for position in ('none','leaf','root'):
                left,right=Store(Path(':memory:'),0),SequentialStore(Path(':memory:'),0)
                try:
                    fixture=list(records)
                    if position != 'none':
                        fixture.append(revocation(leaf if position=='leaf' else records[0]))
                    for store in (left,right):
                        store.set_clock(11);store.ingest(fixture)
                    args=(leaf['id'],leaf['subject'],1,leaf['service'])
                    expected=right.authorize(*args)
                    assert left.authorize(*args)==expected
                    for _ in range(20):
                        left.authorize(*args);right.authorize(*args)
                    samples=[]
                    for pair in range(11):
                        arms=(('sequential',right),('batched',left)) if pair%2==0 else (('batched',left),('sequential',right))
                        times={}
                        for arm,store in arms:
                            start=time.perf_counter_ns()
                            for _ in range(32):
                                current=store.authorize(*args)
                            elapsed=time.perf_counter_ns()-start
                            assert current==expected
                            times[arm]=elapsed/32
                        samples.append(dict(pair=pair,batch=32,**times))
                    ratios=[s['sequential']/s['batched'] for s in samples]
                    results.append(dict(records=records_count,depth=depth,revocation=position,
                                        median_ratio=statistics.median(ratios),
                                        slower_pairs=sum(r<1 for r in ratios),samples=samples))
                finally:
                    left.close();right.close()
    return dict(environment=dict(platform=platform.platform(),processor=platform.processor(),
                                 python=platform.python_version(),sqlite=sqlite3.sqlite_version,affinity=affinity),
                protocol=dict(record_counts=[100,1000,10000],depths=[1,4,16,64],
                              revocation_positions=['none','leaf','root'],pairs=11,batch=32,
                              warmups=20,scope='local in-memory SQLite authorization; excludes RPC, persistence and collector latency'),
                cases=results)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--measure',action='store_true')
    parser.add_argument('--out',type=Path)
    args=parser.parse_args()
    result=measure() if args.measure else check()
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    if args.measure:
        ratios=[r['median_ratio'] for r in result['cases']]
        print(json.dumps(dict(cases=len(ratios),median_range=[min(ratios),max(ratios)],
                              slower_cases=sum(r<1 for r in ratios),environment=result['environment']),indent=2))
    else:
        print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
