import json, resource, tempfile, time
from pathlib import Path
from capability import grant, revocation
from transport import Cluster
from verifier import verify_decision, verify_barrier

def run():
    started=time.perf_counter(); cpu=time.process_time()
    root=grant(0,1,None,7,[1000,1000,1000,200,200],'pilot-root')
    child=grant(1,2,root,3,[1000,1000,1000,200,200],'pilot-child')
    rev=revocation(root); decisions=[]
    with tempfile.TemporaryDirectory() as t:
        with Cluster(Path(t)/'closed') as c:
            for i in range(5): c.rpc(i,{'op':'ingest','events':[root,child],'clock':10})
            rs=[]
            for i in range(3): rs += c.rpc(i,{'op':'ingest','events':[rev],'clock':20})['receipts']
            before=c.rpc(0,{'op':'barrier','revocation':rev,'receipts':rs,'clock':199})
            after=c.rpc(0,{'op':'barrier','revocation':rev,'receipts':rs,'clock':200})
            assert not before['closed'] and after['closed']
            assert verify_barrier(rev,rs,200,0)
            for i in range(5):
                d=c.rpc(i,{'op':'use','cap':child['id'],'actor':2,'right':1,'service':'svc0','clock':200,'snapshot':True})
                assert not d['allow'] and verify_decision(d); decisions.append(d)
            # Actual process termination AFTER a durable receipt, then disk recovery.
            c.restart()
            d=c.rpc(0,{'op':'use','cap':child['id'],'actor':2,'right':1,'service':'svc0','clock':201,'snapshot':True})
            assert d['reason']=='revoked' and verify_decision(d)
            good={'before_closed':before['closed'],'after_closed':after['closed'],'cover':after['cover'],
                  'post_barrier_reasons':[d['reason'] for d in decisions],'post_restart_reason':d['reason'],
                  'messages':c.messages,'wire_bytes':c.sent_bytes+c.received_bytes,
                  'server_peak_rss_kib':c.max_server_rss_kib}
        with Cluster(Path(t)/'volatile',mode='volatile') as c:
            c.rpc(0,{'op':'ingest','events':[root,child,rev],'clock':20})
            assert not c.rpc(0,{'op':'use','cap':child['id'],'actor':2,'right':1,'service':'svc0','clock':21})['allow']
            c.restart()
            bad=c.rpc(0,{'op':'use','cap':child['id'],'actor':2,'right':1,'service':'svc0','clock':22})
            assert bad['allow']
    children=resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'pilot':'receipt-or-expiry-and-process-recovery','gateways':5,'principals':5,
            'capabilities':2,'revocations':1,'worker_processes_at_once':2,'positive':good,
            'negative_control_volatile_ack_resurrected':bad['allow'],
            'wall_s':time.perf_counter()-started,'parent_cpu_s':time.process_time()-cpu,
            'children_cpu_s':children.ru_utime+children.ru_stime,
            'parent_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'decisions':decisions}
if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,default=Path('results'))
    args=parser.parse_args()
    out=run(); p=args.out/'pilot.json'; p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({k:v for k,v in out.items() if k!='decisions'},indent=2))
