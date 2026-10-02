"""Controlled policy comparison over the same five loopback endpoints.

These are policy baselines in the toy implementation, not ports or performance
measurements of WAVE, Zanzibar, or another external authorization system.
"""
import gzip
import json
import resource
import tempfile
import time
from pathlib import Path
from capability import grant, revocation, packed
from transport import Cluster
from verifier import verify_decision

TIMES = [20, 199, 200, 999, 1000, 1499, 1500, 1600]
POLICIES = [
    ('central-fail-closed', 'closed', 'central', [1000]*5),
    ('lease-only', 'lease', 'lease-only', [1000]*5),
    ('all-durable-receipts', 'closed', 'all-receipts', [1000]*5),
    ('uniform-long-plus-receipts', 'closed', 'hybrid', [1000]*5),
    ('uniform-short-plus-receipts', 'closed', 'hybrid', [200]*5),
    ('audience-lease-plus-receipts', 'closed', 'hybrid', [1000,1000,1000,200,200]),
]

def run(outdir=Path('results')):
    outdir.mkdir(exist_ok=True)
    start=time.perf_counter(); cpu=time.process_time(); rows=[]
    with gzip.open(outdir/'policy-trace.jsonl.gz','wt') as log:
        for name,mode,rule,deadlines in POLICIES:
            root=grant(0,1,None,7,deadlines,'policy-target')
            child=grant(1,2,root,3,deadlines,'policy-descendant')
            control=grant(0,2,None,3,deadlines,'policy-unrevoked-control')
            rev=revocation(root); receipts=[]; observed=[]
            with tempfile.TemporaryDirectory() as t:
                with Cluster(Path(t),mode=mode) as c:
                    def rpc(node,q):
                        result=c.rpc(node,q)
                        log.write(json.dumps({'policy':name,'node':node,'request':q,'response':result})+'\n')
                        return result
                    for node in range(5): rpc(node,{'op':'ingest','clock':10,'events':[root,child,control]})
                    for node in range(3): receipts += rpc(node,{'op':'ingest','clock':20,'events':[rev]})['receipts']
                    for tick in TIMES:
                        if tick==1500:
                            for node in [3,4]: receipts += rpc(node,{'op':'ingest','clock':tick,'events':[rev]})['receipts']
                        if rule=='central':
                            # All available requests go to the durable authority.
                            b={'closed':True,'cover':['authority-or-unavailable']*5}
                        else:
                            b=rpc(0,{'op':'barrier','revocation':rev,'receipts':receipts,'clock':tick,'rule':rule})
                        outcomes={}
                        for label,token in [('target',child),('unrevoked',control)]:
                            outcomes[label]=[]
                            for node in range(5):
                                if rule=='central' and node in [3,4] and tick<1500:
                                    d={'allow':False,'reason':'partition-unavailable'}
                                else:
                                    dest=0 if rule=='central' else node
                                    d=rpc(dest,{'op':'use','clock':tick,'cap':token['id'],'actor':2,'right':1,'service':'svc0','snapshot':True})
                                    if mode=='closed': assert verify_decision(d)
                                outcomes[label].append({'allow':d['allow'],'reason':d['reason']})
                        if b['closed']: assert not any(d['allow'] for d in outcomes['target'])
                        observed.append({'tick':tick,'closed':b['closed'],'cover':b['cover'],**outcomes})
                    closes=next(r['tick'] for r in observed if r['closed'])
                    expected={'central-fail-closed':20,'lease-only':1000,'all-durable-receipts':1500,
                              'uniform-long-plus-receipts':1000,'uniform-short-plus-receipts':200,
                              'audience-lease-plus-receipts':200}[name]
                    assert closes==expected
                    rows.append({'policy':name,'deadlines':deadlines,'mode':mode,'rule':rule,
                                 'revocation_tick':20,'healing_tick':1500,'first_observed_closed_tick':closes,
                                 'logical_completion_delay':closes-20,'observations':observed,
                                 'messages':c.messages,'wire_bytes':c.sent_bytes+c.received_bytes,
                                 'server_peak_rss_kib':c.max_server_rss_kib})
    child=resource.getrusage(resource.RUSAGE_CHILDREN)
    out={'ticks':TIMES,'units':'logical milliseconds, not a wall-clock network latency claim',
         'baseline_scope':'policy emulations in one toy service; not external system implementations',
         'policies':rows,'wall_s':time.perf_counter()-start,'parent_cpu_s':time.process_time()-cpu,
         'children_cpu_s':child.ru_utime+child.ru_stime,
         'parent_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    (outdir/'policies.json').write_text(json.dumps(out,indent=2)+'\n')
    return out

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,default=Path('results'))
    args=parser.parse_args()
    out=run(args.out)
    print(json.dumps({'completion_delays':{x['policy']:x['logical_completion_delay'] for x in out['policies']},
                      'wall_s':out['wall_s'],'parent_cpu_s':out['parent_cpu_s'],'children_cpu_s':out['children_cpu_s']},indent=2))
