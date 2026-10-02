"""One admissible clock trace distinguishes local time-guard denial from real expiry."""
from __future__ import annotations
import argparse,gzip,json,resource,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from capability import grant,revocation
from transport import Cluster
from verifier import verify_decision,verify_barrier

def run(out: Path) -> dict:
    out.mkdir(parents=True,exist_ok=True); start=time.perf_counter(); cpu=time.process_time()
    target=grant(0,1,None,1,[10]*5,'local-clock-regression'); revoke=revocation(target); rows=[]
    with tempfile.TemporaryDirectory() as directory,gzip.open(out/'clock-regression-trace.jsonl.gz','wt') as log:
        with Cluster(Path(directory),epsilon=2) as cluster:
            def rpc(actual,request):
                assert abs(actual-request['clock'])<=2
                response=cluster.rpc(0,request)
                log.write(json.dumps({'actual_time':actual,'node':0,'request':request,'response':response})+'\n')
                return response
            rpc(8,{'op':'ingest','clock':8,'events':[target]})
            for actual,clock,operation,expected in [(8,10,'use',False),(9,7,'use',True),
                                                    (10,12,'barrier',True),(11,9,'barrier',False),(11,9,'use',False)]:
                q={'op':operation,'clock':clock}
                if operation=='use':
                    q.update(cap=target['id'],actor=1,right=1,service='svc0',snapshot=True)
                    response=rpc(actual,q);assert verify_decision(response);value=response['allow']
                    reason=response['reason']
                else:
                    q.update(revocation=revoke,receipts=[])
                    response=rpc(actual,q);value=response['closed'];reason=None
                    assert value==verify_barrier(revoke,[],clock,2)
                assert value==expected
                rows.append({'actual_time':actual,'clock':clock,'operation':operation,'value':value,'reason':reason})
            messages=cluster.messages;wire=cluster.sent_bytes+cluster.received_bytes;rss=cluster.max_server_rss_kib
    child=resource.getrusage(resource.RUSAGE_CHILDREN)
    result={'deadline':10,'epsilon':2,'observations':rows,'messages':messages,'wire_bytes':wire,
      'server_peak_rss_kib':rss,'wall_s':time.perf_counter()-start,'parent_cpu_s':time.process_time()-cpu,
      'children_cpu_s':child.ru_utime+child.ru_stime,'parent_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
      'scope':'Post-inspection trace: an early conservative time-guard rejection may become an allow before actual expiry. A genuine closure certificate still excludes all later use.'}
    (out/'clock-regression.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=Path('results'));args=parser.parse_args()
    print(json.dumps(run(args.out),indent=2))
