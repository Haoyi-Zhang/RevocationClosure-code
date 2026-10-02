"""Post-inspection clock-boundary checks; not part of the frozen latency grid.

Exhaust finite admissible clock readings and retain a real loopback counterexample
for monotone *poll status*, not for revocation safety. No physical clocks measured.
"""
from __future__ import annotations
import argparse,gzip,json,resource,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from capability import grant,revocation,barrier
from transport import Cluster
from verifier import verify_decision

def run(out: Path) -> dict:
    out.mkdir(parents=True,exist_ok=True)
    start=time.perf_counter();cpu=time.process_time();readings=0;early=0;late=0;closed=0
    for epsilon in (0,1,2,4):
        for deadline in range(1,17):
            r=revocation(grant(0,1,None,1,[deadline]*5,f'clock-{epsilon}-{deadline}'))
            for actual in range(deadline+2*epsilon+3):
                for clock in range(max(0,actual-epsilon),actual+epsilon+1):
                    readings+=1
                    allowed=clock+epsilon<deadline
                    cert=barrier(r,[],clock,epsilon)['closed']
                    if allowed: assert actual<deadline
                    if cert: assert actual>=deadline;closed+=1
                    if actual<deadline-2*epsilon:
                        assert allowed;early+=1
                    if actual>=deadline+2*epsilon:
                        assert cert;late+=1
    target=grant(0,1,None,1,[10]*5,'clock-backward-status')
    r=revocation(target)
    with tempfile.TemporaryDirectory() as directory,gzip.open(out/'clock-bounds-trace.jsonl.gz','wt') as trace:
        with Cluster(Path(directory),epsilon=2) as cluster:
            def rpc(node: int,actual: int,request: dict) -> dict:
                assert abs(request['clock']-actual)<=2
                response=cluster.rpc(node,request)
                trace.write(json.dumps({'node':node,'actual_time':actual,'request':request,'response':response})+'\n')
                return response
            for i in range(5): rpc(i,8,{'op':'ingest','clock':8,'events':[target]})
            before=rpc(0,10,{'op':'barrier','clock':12,'revocation':r,'receipts':[]})
            after=rpc(0,11,{'op':'barrier','clock':9,'revocation':r,'receipts':[]})
            assert before['closed'] and not after['closed']
            decisions=[]
            for i in range(5):
                answer=rpc(i,11,{'op':'use','clock':9,'cap':target['id'],'actor':1,'right':1,'service':'svc0','snapshot':True})
                assert not answer['allow'] and verify_decision(answer)
                decisions.append(answer['reason'])
            messages=cluster.messages;wire=cluster.sent_bytes+cluster.received_bytes;rss=cluster.max_server_rss_kib
    child=resource.getrusage(resource.RUSAGE_CHILDREN)
    result={'admissible_clock_readings':readings,'guaranteed_early_use_readings':early,
        'guaranteed_late_closure_readings':late,'closed_readings':closed,
        'status_counterexample':{'epsilon':2,'deadline':10,'actual_times':[10,11],
            'collector_clocks':[12,9],'closed':[before['closed'],after['closed']],
            'post_closure_reasons':decisions},
        'messages':messages,'wire_bytes':wire,'server_peak_rss_kib':rss,
        'wall_s':time.perf_counter()-start,'parent_cpu_s':time.process_time()-cpu,
        'children_cpu_s':child.ru_utime+child.ru_stime,'parent_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'scope':'Post-inspection finite clock-boundary check. The stateless collector can reopen its poll status after bounded clock regression; no post-certificate authorization becomes valid.'}
    (out/'clock-bounds.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=Path('results'));args=parser.parse_args()
    print(json.dumps(run(args.out),indent=2))
