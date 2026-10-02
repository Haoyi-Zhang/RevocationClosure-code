"""Exact bounded enumerations, not a machine-checked unbounded proof."""
from __future__ import annotations
import gzip,itertools,json,resource,time
from pathlib import Path
from capability import Store,grant,revocation,receipt,barrier,sign,packed
from verifier import verify_barrier,verify_decision,typed

def run(out: Path):
    started=time.perf_counter(); cpu=time.process_time(); out.mkdir(parents=True,exist_ok=True)
    instances=accepted=uncovered=0
    with gzip.open(out/'finite-barriers.jsonl.gz','wt') as raw:
        for vector in itertools.product((3,6),repeat=5):
            root=grant(0,1,None,7,list(vector),'finite-barrier'); rev=revocation(root)
            all_rs=[receipt(i,rev) for i in range(5)]
            for mask in range(32):
                rs=[r for i,r in enumerate(all_rs) if mask&(1<<i)]
                for clock in range(2,11):
                    for eps in (0,1,2):
                        # A coordinate is covered by a durable receipt or by
                        # a sound lower time bound. Integer clocks, fixed N=5.
                        b=barrier(rev,rs,clock,eps); other=verify_barrier(rev,rs,clock,eps)
                        assert b['closed']==other
                        lower=clock-eps
                        open_nodes=[i for i in range(5) if not(mask&(1<<i)) and lower<vector[i]]
                        assert b['closed']==(not open_nodes)
                        if b['closed']:
                            accepted+=1
                            for true_time in range(lower,13):
                                for offset in range(-eps,eps+1):
                                    for i in range(5):
                                        if true_time+offset<0: continue
                                        assert mask&(1<<i) or true_time+offset+eps>=vector[i]
                        else:
                            uncovered+=1
                            # An observationally consistent extension has a
                            # valid hidden grant at an open gateway. At actual
                            # time lower, that gateway's slow clock permits use.
                            i=open_nodes[0]; local_clock=max(0,lower-eps)
                            assert local_clock+eps<vector[i]
                            assert abs(clock-lower)<=eps and abs(local_clock-lower)<=eps
                        raw.write(json.dumps({'deadlines':vector,'receipt_mask':mask,'clock':clock,
                                              'epsilon':eps,'closed':b['closed'],'open_nodes':open_nodes})+'\n')
                        instances+=1
    decisions=0; reasons={}
    # Rights masks 1..7; good/bad issuer; good/bad deadline; all 8 event
    # subsets; all 5 gateways and three boundary times. No sampled cases.
    with gzip.open(out/'finite-decisions.jsonl.gz','wt') as raw:
        for pr,cr,issuer_ok,deadline_ok in itertools.product(range(1,8),range(1,8),(False,True),(False,True)):
            root=grant(0,1,None,pr,[10]*5,'finite-root')
            child=grant(1 if issuer_ok else 2,3,root,cr,[10 if deadline_ok else 11]*5,'finite-child')
            rev=revocation(root); events=[root,child,rev]
            for mask in range(8):
                batch=[e for i,e in enumerate(events) if mask&(1<<i)]
                for node in range(5):
                    with_store=Store(Path(':memory:'),node)
                    try:
                        with_store.ingest(batch)
                        for clock in (5,10,11):
                            with_store.set_clock(clock)
                            d=with_store.authorize(child['id'],3,1,'svc0',True)
                            assert verify_decision(d)
                            reasons[d['reason']]=reasons.get(d['reason'],0)+1; decisions+=1
                            raw.write(json.dumps({'parent_rights':pr,'child_rights':cr,'issuer_ok':issuer_ok,
                                'deadline_ok':deadline_ok,'event_mask':mask,'node':node,'clock':clock,
                                'reason':d['reason'],'allow':d['allow']})+'\n')
                    finally: with_store.close()
    # All 120 permutations of five labeled message slots, one a duplicate.
    a=grant(0,1,None,7,[100]*5,'order-root'); b=grant(1,2,a,3,[100]*5,'order-child')
    c=grant(2,3,b,1,[100]*5,'order-grandchild'); r=revocation(a)
    slots=[a,b,c,r,b]; schedule_decisions=0; final_states=set()
    with gzip.open(out/'finite-orders.jsonl.gz','wt') as raw:
        for perm in itertools.permutations(range(5)):
            s=Store(Path(':memory:'),0); trace=[]
            try:
                for tick,idx in enumerate(perm,1):
                    s.set_clock(tick); s.ingest([slots[idx]])
                    d=s.authorize(c['id'],3,1,'svc0',True); assert verify_decision(d)
                    trace.append(d['reason']); schedule_decisions+=1
                final_states.add(tuple(e['id'] for e in s.events()))
                assert not d['allow'] and d['reason']=='revoked'
                raw.write(json.dumps({'permutation':perm,'decisions':trace})+'\n')
            finally: s.close()
    assert len(final_states)==1
    # Own malformed/unsupported record fixtures; no exploitation of a service.
    bad=[]
    for field,val in [('rights',0),('rights',True),('subject',9),('deadlines',[1,2]),('nonce',''),('service','other')]:
        body={k:v for k,v in a.items() if k not in ('id','mac')};body[field]=val;bad.append(sign(body))
    corrupt=dict(a);corrupt['rights']=2;bad.append(corrupt)
    assert all(not typed(x) for x in bad)
    s=Store(Path(':memory:'),0)
    try:
        for x in bad:
            try:s.ingest([x])
            except ValueError:pass
            else:raise AssertionError('malformed admitted')
        assert not s.events()
    finally:s.close()
    result={'barrier_instances':instances,'closed_certificates':accepted,'uncovered_counterextensions':uncovered,
            'local_decisions':decisions,'reason_counts':reasons,'labeled_schedule_permutations':120,
            'schedule_decisions':schedule_decisions,'distinct_final_states':len(final_states),'malformed_rejected':len(bad),
            'wall_s':time.perf_counter()-started,'parent_cpu_s':time.process_time()-cpu,'children_cpu_s':0,
            'parent_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'boundary':'Exact stated finite products only; in-memory stores; no durability or exhaustive unbounded schedule claim.'}
    (out/'finite.json').write_text(json.dumps(result,indent=2)+'\n'); return result

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=Path('results'));a=p.parse_args()
    print(json.dumps(run(a.out),indent=2))
