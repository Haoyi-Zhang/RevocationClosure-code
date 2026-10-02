"""Loopback lookup scaling; not WAN, production credential, or deployment data."""
from __future__ import annotations
import argparse,csv,gzip,json,random,resource,tempfile,time
from pathlib import Path
from capability import grant
from transport import Cluster
from verifier import Replay

def run(records,depth,seed,out):
    if records not in (100,1000,5000,10000) or depth not in (1,4,16,64) or seed not in (17,29,43):raise ValueError('outside frozen grid')
    out.mkdir(parents=True,exist_ok=True);name='scale-%d-%d-%d'%(records,depth,seed)
    started=time.perf_counter();cpu=time.process_time();old=resource.getrusage(resource.RUSAGE_CHILDREN)
    rng=random.Random(seed);gs=[];parent=None
    for j in range(depth):
        issuer=0 if parent is None else parent['subject'];parent=grant(issuer,(issuer+1)%5,parent,255,[500000]*5,'chain-'+str(j));gs.append(parent)
    leaf=parent
    for j in range(depth,records):gs.append(grant(j%5,(j+1)%5,None,255,[500000]*5,'filler-'+str(j)))
    rng.shuffle(gs)
    with gzip.open(out/(name+'-input.json.gz'),'wt') as f:json.dump({'records':gs,'leaf':leaf['id'],'seed':seed},f,sort_keys=True)
    oracle=Replay(0);oracle.ingest(gs);timings=[]
    with tempfile.TemporaryDirectory() as tmp:
        with Cluster(Path(tmp)/'state') as c:
            for offset in range(0,len(gs),256):c.rpc(0,{'op':'ingest','events':gs[offset:offset+256],'clock':1})
            stats=c.rpc(0,{'op':'stats'});assert stats['records']==records
            for j in range(220):
                q={'op':'use','cap':leaf['id'],'actor':leaf['subject'],'right':1,'service':leaf['service'],'clock':j+2}
                r=c.rpc(0,q);assert r['allow']
                request={k:q[k] for k in ('cap','actor','right','service')}
                t=time.perf_counter_ns();reason,atom=oracle.decide(request,q['clock']);vtime=time.perf_counter_ns()-t
                assert (reason,atom)==(r['reason'],r['atom'])
                if j>=20:timings.append({'query':j-20,'rpc_ns':r['rpc_ns'],'service_ns':r['service_ns'],'verifier_ns':vtime})
            messages=c.messages;wire=c.sent_bytes+c.received_bytes;server_rss=c.max_server_rss_kib
    with (out/(name+'.csv')).open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['query','rpc_ns','service_ns','verifier_ns']);writer.writeheader();writer.writerows(timings)
    summary={}
    for key in ('rpc_ns','service_ns','verifier_ns'):
        values=sorted(x[key] for x in timings)
        for label,p in (('median',.5),('p95',.95),('p99',.99)):
            summary[key.replace('_ns','_')+label+'_us']=values[int(p*(len(values)-1))]/1000
    new=resource.getrusage(resource.RUSAGE_CHILDREN)
    result={'records':records,'depth':depth,'seed':seed,'measured_queries':200,'warmup_queries':20,
        'messages':messages,'wire_bytes':wire,'server_peak_rss_kib':server_rss,
        'parent_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'logical_json_bytes':stats['json_bytes'],'allocated_sqlite_bytes':stats['sqlite_bytes'],
        'wall_s':time.perf_counter()-started,'parent_cpu_s':time.process_time()-cpu,
        'children_cpu_s':new.ru_utime+new.ru_stime-old.ru_utime-old.ru_stime,**summary}
    (out/(name+'.json')).write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--records',type=int,required=True);p.add_argument('--depth',type=int,required=True);p.add_argument('--seed',type=int,required=True);p.add_argument('--out',type=Path,default=Path('results'));a=p.parse_args()
    print(json.dumps(run(a.records,a.depth,a.seed,a.out),indent=2))
