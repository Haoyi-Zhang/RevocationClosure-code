"""Frozen-seed network histories over real, separately addressed TCP endpoints.

This emulator schedules benign synthetic events; it does not generate attacks on
any external target. Every accepted request is independently replayed.
"""
from __future__ import annotations
import argparse,collections,gzip,json,random,resource,tempfile,time
from pathlib import Path
from capability import grant,revocation,sign
from transport import Cluster
from verifier import Replay,verify_barrier

SEEDS=(101,211,307,401,503,601,701,809)

def generate(seed):
    rng=random.Random(seed); gs=[];depths={};mutated=0
    for j in range(256):
        if j<16:
            issuer=j%5;g=grant(issuer,(issuer+1)%5,None,255,[800-j,850-j,900-j,450-j,500-j],'tree-'+str(j));dep=1
        else:
            eligible=[x for x in gs if depths[x['id']]<12];parent=rng.choice(eligible)
            rights=parent['rights']&rng.randrange(1,256)
            if not rights:rights=parent['rights']&-parent['rights']
            g=grant(parent['subject'],rng.randrange(5),parent,rights,[max(1,d-rng.randrange(10)) for d in parent['deadlines']],'tree-'+str(j));dep=depths[parent['id']]+1
            if j%29==0:
                b={k:v for k,v in g.items() if k not in ('id','mac')}
                if j%3==0:b['rights']|=1<<8
                elif j%3==1:b['deadlines'][0]=parent['deadlines'][0]+1
                else:b['issuer']=(parent['subject']+1)%5
                g=sign(b);mutated+=1
        gs.append(g);depths[g['id']]=dep
    revs=[revocation(g) for g in rng.sample(gs,32)]
    steps=[];seq=0;dropped=[];duplicated=0
    for ei,e in enumerate(gs+revs):
        birth=0 if ei<16 else rng.randrange(1,30) if ei<256 else 40+(ei-256)%7
        for node in range(5):
            if node!=e['issuer'] and rng.random()<.18:
                dropped.append({'event':e['id'],'node':node});continue
            due=birth+rng.randrange(1,90)
            if node in (3,4) and 30<=due<170:due=170+rng.randrange(20)
            steps.append((due,0,seq,node,{'op':'ingest','events':[e]}));seq+=1
            if rng.random()<.2:
                extra=due+rng.randrange(1,35)
                if node in (3,4) and 30<=extra<170:extra=170+rng.randrange(20)
                steps.append((extra,0,seq,node,{'op':'ingest','events':[e]}));seq+=1;duplicated+=1
    for j in range(1000):
        g=rng.choice(gs);node=rng.randrange(5);tick=rng.randrange(250)
        q={'op':'use','cap':g['id'],'actor':g['subject'],'right':g['rights']&-g['rights'],'service':g['service']}
        if j%31==0:q['actor']=(q['actor']+1)%5
        if j%37==0:q['service']='svc'+str((int(q['service'][-1])+1)%5)
        if j%41==0:q['right']=1<<30
        steps.append((tick,2,seq,node,q));seq+=1
    for tick in (75,150):steps.append((tick,1,seq,0,{'op':'restart'}));seq+=1
    for tick in (150,200):steps.append((tick,3,seq,0,{'op':'poll'}));seq+=1
    steps.sort()
    epsilon=(0,1,3,10)[(seed//100)%4];offsets=[rng.randint(-epsilon,epsilon) for _ in range(5)]
    return gs,revs,steps,{'seed':seed,'epsilon':epsilon,'clock_offsets':offsets,'capabilities':256,'revocations':32,
        'maximum_generated_depth':max(depths.values()),'mutated_signed_grants':mutated,'dropped_deliveries':dropped,
        'duplicate_slots':duplicated,'partition_gateways':[3,4],'partition_interval':[30,170]}

def run(seed,out):
    if seed not in SEEDS:raise ValueError('seed is outside frozen campaign')
    out.mkdir(parents=True,exist_ok=True);started=time.perf_counter();cpu=time.process_time();old=resource.getrusage(resource.RUSAGE_CHILDREN)
    gs,revs,steps,fixture=generate(seed);eps=fixture['epsilon'];offsets=fixture['clock_offsets']
    mirrors=[Replay(i,eps) for i in range(5)];rs=collections.defaultdict(list)
    counts=collections.Counter();latencies=[];closed=barrier_checks=postchecks=0
    with gzip.open(out/('history-%d-input.json.gz'%seed),'wt') as f:
        json.dump({'configuration':fixture,'grants':gs,'revocations':revs,'schedule':steps},f,sort_keys=True)
    with tempfile.TemporaryDirectory() as tmp, gzip.open(out/('history-%d-trace.jsonl.gz'%seed),'wt') as log:
        with Cluster(Path(tmp)/'state',epsilon=eps) as c:
            def rpc(node,q,tick):
                q=dict(q,clock=max(0,tick+offsets[node]));r=c.rpc(node,q)
                log.write(json.dumps({'actual_time':tick,'node':node,'request':q,'response':r},sort_keys=True)+'\n')
                if q['op']=='ingest':
                    mirrors[node].ingest(q['events'])
                    for rec in r['receipts']:rs[rec['revocation']].append(rec)
                elif q['op']=='use':
                    request={k:q[k] for k in ('cap','actor','right','service')}
                    reason,atom=mirrors[node].decide(request,q['clock'])
                    assert (reason,atom,reason=='allow')==(r['reason'],r['atom'],r['allow'])
                    counts[reason]+=1;latencies.append(r['rpc_ns'])
                elif q['op']=='compact':
                    mirrors[node].compact(q['clock']);assert mirrors[node].floor==r['floor']
                return r
            def poll(tick):
                nonlocal closed,barrier_checks,postchecks
                for rev in revs:
                    b=rpc(0,{'op':'barrier','revocation':rev,'receipts':rs[rev['id']]},tick)
                    assert b['closed']==verify_barrier(rev,rs[rev['id']],max(0,tick+offsets[0]),eps)
                    barrier_checks+=1
                    if b['closed']:
                        closed+=1;g=rev['target']
                        for node in range(5):
                            d=rpc(node,{'op':'use','cap':g['id'],'actor':g['subject'],'right':g['rights']&-g['rights'],'service':g['service']},tick)
                            assert not d['allow'];postchecks+=1
            for tick,priority,seq,node,q in steps:
                if q['op']=='restart':
                    c.restart();log.write(json.dumps({'actual_time':tick,'op':'process_restart_after_replies'})+'\n')
                elif q['op']=='poll':poll(tick)
                else:rpc(node,q,tick)
            # Explicit pull/push anti-entropy: real exports and ingress frames,
            # with the scheduler transporting bytes rather than consulting a
            # central authorization database. Intentional drops are healed here.
            exports=[rpc(i,{'op':'export'},250)['events'] for i in range(5)]
            before_states=len({tuple(sorted(e['id'] for e in x)) for x in exports})
            union={e['id']:e for x in exports for e in x}
            assert set(union)=={e['id'] for e in gs+revs}
            anti_entropy_records=0
            for node,x in enumerate(exports):
                known={e['id'] for e in x};missing=[union[k] for k in sorted(union) if k not in known]
                if missing:rpc(node,{'op':'ingest','events':missing},250);anti_entropy_records+=len(missing)
            finals=[rpc(i,{'op':'export'},251)['events'] for i in range(5)]
            assert len({tuple(sorted(e['id'] for e in x)) for x in finals})==1
            for i,x in enumerate(finals):assert {e['id'] for e in x}==set(mirrors[i].records)
            poll(251);poll(1000)
            # A common normalized floor is explicitly established. Different
            # offset clocks receive adjusted actual times, all after prior use.
            for i in sorted(range(5),key=lambda j:1100-offsets[j]+eps):
                target_actual=1100-offsets[i]+eps
                rpc(i,{'op':'compact'},target_actual)
                assert mirrors[i].floor==1100
            for i in range(5):
                replay=rpc(i,{'op':'ingest','events':gs+revs},1200)
                assert replay['added']==0 and replay['dropped']==len(gs)+len(revs)
                assert rpc(i,{'op':'stats'},1200)['records']==0
            metrics={'messages':c.messages,'wire_bytes':c.sent_bytes+c.received_bytes,'server_peak_rss_kib':c.max_server_rss_kib}
    # Do not interpret across-seed percentiles as deployment uncertainty.
    ls=sorted(latencies)
    result={'seed':seed,'epsilon':eps,'clock_offsets':offsets,'logical_generated_events':len(gs)+len(revs),
        'scheduled_use_requests':1000,'all_use_checks':sum(counts.values()),'reason_counts':dict(counts),
        'barrier_checks':barrier_checks,'closed_certificates':closed,'post_barrier_use_checks':postchecks,
        'process_restarts':2,'distinct_states_before_anti_entropy':before_states,'states_after_anti_entropy':1,
        'anti_entropy_records':anti_entropy_records,'records_after_common_floor_and_replay':0,
        'dropped_deliveries':len(fixture['dropped_deliveries']),'duplicate_slots':fixture['duplicate_slots'],
        'rpc_median_us':ls[len(ls)//2]/1000,'rpc_p95_us':ls[int(.95*(len(ls)-1))]/1000,
        'wall_s':time.perf_counter()-started,'parent_cpu_s':time.process_time()-cpu,
        'parent_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,**metrics}
    new=resource.getrusage(resource.RUSAGE_CHILDREN);result['children_cpu_s']=new.ru_utime+new.ru_stime-old.ru_utime-old.ru_stime
    (out/('history-%d.json'%seed)).write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--seed',type=int,required=True);p.add_argument('--out',type=Path,default=Path('results'));a=p.parse_args()
    print(json.dumps(run(a.seed,a.out),indent=2))
