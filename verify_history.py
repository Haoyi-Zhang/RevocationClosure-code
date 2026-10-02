"""Offline verification of retained local-view histories; no service imports."""
import argparse,gzip,json
from pathlib import Path
from verifier import Replay,verify_barrier

def verify(path):
    seed=int(path.name.split('-')[1]);fixture=path.with_name('history-%d-input.json.gz'%seed)
    with gzip.open(fixture,'rt') as f:conf=json.load(f)['configuration']
    eps=conf['epsilon'];mirrors=[Replay(i,eps) for i in range(5)]
    uses=barriers=rows=0;last=-1
    with gzip.open(path,'rt') as f:
        for line in f:
            d=json.loads(line);rows+=1;t=d['actual_time'];assert t>=last,(path,rows,'nonmonotone time');last=t
            if d.get('op')=='process_restart_after_replies':continue
            node=d['node'];q=d['request'];r=d['response'];assert abs(q['clock']-t)<=eps
            if q['op']=='ingest':mirrors[node].ingest(q['events'])
            elif q['op']=='compact':
                mirrors[node].compact(q['clock']);assert r['floor']==mirrors[node].floor
            elif q['op']=='use':
                request={k:q[k] for k in ('cap','actor','right','service')}
                reason,atom=mirrors[node].decide(request,q['clock'])
                assert (r['reason'],r['atom'],r['allow'])==(reason,atom,reason=='allow');uses+=1
            elif q['op']=='barrier':
                assert verify_barrier(q['revocation'],q['receipts'],q['clock'],eps)==r['closed'];barriers+=1
            elif q['op']=='export':assert {x['id'] for x in r['events']}==set(mirrors[node].records)
            elif q['op']=='stats':assert r['records']==len(mirrors[node].records)
            else:raise AssertionError('unknown logged operation')
    assert all(not m.records and m.floor==1100 for m in mirrors)
    return {'seed':seed,'rows':rows,'use_checks':uses,'barrier_checks':barriers,'clock_order_checked':True}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,default=Path('results'));a=p.parse_args()
    reports=[verify(x) for x in sorted(a.directory.glob('history-*-trace.jsonl.gz'))]
    assert len(reports)==8,'eight frozen histories required'
    print(json.dumps({'verified':reports},indent=2))
