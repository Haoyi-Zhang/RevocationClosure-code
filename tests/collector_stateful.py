"""Frozen seed/profile cross-product; SQL reopens are not process crashes."""
from __future__ import annotations
import argparse,gzip,json,random,resource,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from capability import Store,grant,revocation,packed
from collector import ClosureJournal
from verifier import verify_decision
SEEDS=[101,211,307,401,503,601,701,809,907,1009,1103,1201,1301,1409,1511,1601]
PROFILES=['receipt-rich','expiry-only','mixed','hidden-lineage']

def run(out):
    began=time.perf_counter();cpu=time.process_time();out.mkdir(parents=True,exist_ok=True)
    totals=dict(traces=0,steps=0,authorization_comparisons=0,postclosure_decisions=0,
                gateway_reopens=0,collector_reopens=0,compactions=0,replays=0,
                hidden_deliveries=0,mismatches=0,postclosure_allows=0,status_regressions=0)
    summaries=[]
    with gzip.open(out/'collector-stateful-trace.jsonl.gz','wt') as trace:
        for pi,profile in enumerate(PROFILES):
            for seed in SEEDS:
                rng=random.Random(seed+10000*pi)
                with tempfile.TemporaryDirectory() as td:
                    d=Path(td);ds=[40,70,100,130,160] if pi<2 else [160,160,160,40,60]
                    root=grant(0,1,None,3,[200]*5,f'r-{profile}-{seed}')
                    target=grant(1,2,root,1,ds,f't-{profile}-{seed}')
                    child=grant(2,3,target,1,ds,f'c-{profile}-{seed}');rev=revocation(target)
                    stores=[Store(d/f'g{i}.sqlite',i,2) for i in range(5)]
                    journal=ClosureJournal(d/'collector.sqlite',rev,2)
                    hidden=profile=='hidden-lineage';delivered=not hidden
                    for s in stores:s.ingest([root,target]+([] if hidden else [child]))
                    available={};actual=0;seen=False;first=None;post=0
                    try:
                        for step in range(160):
                            actual+=rng.randint(1,3);actions=[]
                            if hidden and seen and not delivered:
                                for s in stores:s.ingest([root,target,child])
                                delivered=True;totals['hidden_deliveries']+=5;actions.append('hidden-arrival')
                            if profile!='expiry-only' and rng.random()<.4:
                                i=rng.choice(list(range(5)) if pi==0 else [0,1,2])
                                stores[i].set_clock(rng.randint(max(0,actual-2),actual+2))
                                available[i]=stores[i].ingest([rev])['receipts'][0];actions.append(f'revoke-{i}')
                            if rng.random()<.15:
                                i=rng.randrange(5);stores[i].set_clock(rng.randint(max(0,actual-2),actual+2))
                                stores[i].compact();totals['compactions']+=1;actions.append(f'compact-{i}')
                            if rng.random()<.18:
                                i=rng.randrange(5);stores[i].ingest([root,target]+([child] if delivered else []))
                                totals['replays']+=1;actions.append(f'replay-{i}')
                            if rng.random()<.12:
                                i=rng.randrange(5);stores[i].close();stores[i]=Store(d/f'g{i}.sqlite',i,2)
                                totals['gateway_reopens']+=1;actions.append(f'reopen-{i}')
                            if rng.random()<.12:
                                journal.close();journal=ClosureJournal(d/'collector.sqlite',rev,2)
                                totals['collector_reopens']+=1;actions.append('reopen-collector')
                            batch=[r for _,r in sorted(available.items()) if rng.random()<.65]
                            if batch and rng.random()<.3:batch.append(batch[0])
                            clock=rng.randint(max(0,actual-2),actual+2);state=journal.observe(clock,batch)
                            if seen and not state['closed']:
                                totals['status_regressions']+=1;raise AssertionError('status regression')
                            if state['closed'] and not seen:first=dict(step=step,time=actual,cover=state['cover'])
                            seen|=state['closed'];decisions=[]
                            for i,s in enumerate(stores):
                                c=rng.randint(max(0,actual-2),actual+2);s.set_clock(c)
                                ans=s.authorize(child['id'],3,1,'svc0',True)
                                if not verify_decision(ans):
                                    totals['mismatches']+=1;raise AssertionError('differential mismatch')
                                totals['authorization_comparisons']+=1
                                if seen:
                                    post+=1;totals['postclosure_decisions']+=1
                                    if ans['allow']:
                                        totals['postclosure_allows']+=1;raise AssertionError('postclosure use')
                                decisions.append(dict(node=i,clock=c,floor=ans['floor'],allow=ans['allow'],reason=ans['reason']))
                            trace.write(packed(dict(profile=profile,seed=seed,step=step,time=actual,
                                                   collector_clock=clock,collector=state,actions=actions,
                                                   decisions=decisions)).decode()+'\n')
                            totals['steps']+=1
                        assert seen and post>0 and delivered
                        for db in [journal.db]+[s.db for s in stores]:assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
                    finally:
                        journal.close()
                        for s in stores:s.close()
                    totals['traces']+=1;summaries.append(dict(profile=profile,seed=seed,first_closed=first,postclosure_decisions=post))
    result=dict(**totals,trace_summaries=summaries,wall_s=time.perf_counter()-began,
                parent_cpu_s=time.process_time()-cpu,parent_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    (out/'collector-stateful.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
    if not __debug__:raise RuntimeError('Do not use -O')
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=Path('results'));r=run(p.parse_args().out)
    print(json.dumps({k:v for k,v in r.items() if k!='trace_summaries'},indent=2))
