"""Bounded admission/chain/clock checks. Only owned synthetic loopback state."""
import gzip
import hashlib
import hmac
import json
import resource
import socket
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from capability import (Store, grant, revocation, receipt, sign, barrier, shape, packed,
                        PRINCIPAL_KEYS, receipt_authenticated,
                        MAX_RECORDS, MAX_GRANT_WIRE, MAX_EVENT_WIRE,
                        MAX_REPLY_WIRE, MAX_REPLY_OVERHEAD, MAX_TIME)
from transport import Cluster
from verifier import verify_decision, typed

def run(out=Path('results')):
    start=time.perf_counter(); cpu=time.process_time(); results=[]
    out=Path(out); out.mkdir(parents=True,exist_ok=True)
    tokens=[grant(0,1,None,7,[1000]*5,'capacity-%d'%j) for j in range(MAX_RECORDS)]
    atomic_revoke=revocation(tokens[0])
    atomic_overflow=grant(0,1,None,7,[1000]*5,'capacity-transaction-overflow')
    with gzip.open(out/'boundary-capacity-input.json.gz','wt') as f:
        json.dump({'capacity_tokens':tokens,
                   'atomic_batch':[atomic_revoke,atomic_overflow]},f,
                  sort_keys=True,separators=(',',':'))

    # A late failure must roll back both durable and volatile effects from the
    # whole batch.  The volatile mode is intentionally non-durable across a
    # restart, but it is not allowed to leak an in-memory revocation from a
    # failed RPC.
    with tempfile.TemporaryDirectory() as transaction_dir:
        transaction_dir=Path(transaction_dir)
        closed=Store(transaction_dir/'closed.sqlite',0)
        closed.set_clock(1)
        closed.ingest(tokens[:-1])
        try:
            closed.ingest([atomic_revoke,atomic_overflow])
        except ValueError as e:
            assert 'record limit' in str(e)
        else:
            raise AssertionError('closed batch was not rolled back at capacity')
        closed_decision=closed.authorize(tokens[0]['id'],1,1,'svc0',with_snapshot=True)
        assert closed.stats()['records']==MAX_RECORDS-1
        assert closed_decision['allow'] and verify_decision(closed_decision)
        assert not any(e['kind']=='revoke' for e in closed.events())
        closed.close()

        volatile=Store(transaction_dir/'volatile.sqlite',0,mode='volatile')
        volatile.set_clock(1)
        volatile.ingest(tokens)
        try:
            volatile.ingest([atomic_revoke,atomic_overflow])
        except ValueError as e:
            assert 'record limit' in str(e)
        else:
            raise AssertionError('volatile batch was not rolled back at capacity')
        volatile_decision=volatile.authorize(tokens[0]['id'],1,1,'svc0',with_snapshot=True)
        assert volatile.stats()['records']==MAX_RECORDS
        assert volatile.volatile=={}
        assert volatile_decision['allow'] and verify_decision(volatile_decision)
        volatile.close()
    results.append({'case':'batch-transaction-atomicity',
                    'closed_late_capacity_failure_rolled_back':True,
                    'volatile_late_capacity_failure_rolled_back':True,
                    'failed_batch_receipt_returned':False,
                    'authority_remained_usable':True})
    with tempfile.TemporaryDirectory() as t, gzip.open(out/'boundary-trace.jsonl.gz','wt') as f:
        with Cluster(Path(t)) as c:
            def rpc(node,q):
                try:
                    v=c.rpc(node,q); f.write(json.dumps({'node':node,'request':q,'response':v})+'\n');return v
                except ValueError as e:
                    f.write(json.dumps({'node':node,'request':q,'error':str(e)})+'\n');raise
            for j in range(0,MAX_RECORDS,256): rpc(0,{'op':'ingest','clock':1,'events':tokens[j:j+256]})
            assert rpc(0,{'op':'stats'})['records']==MAX_RECORDS
            assert rpc(0,{'op':'ingest','clock':2,'events':[tokens[0]]})['added']==0
            r=revocation(tokens[0])
            try: rpc(0,{'op':'ingest','clock':3,'events':[tokens[1],r]})
            except ValueError as e: assert 'record limit' in str(e)
            else: raise AssertionError('capacity overflow')
            assert rpc(0,{'op':'stats'})['records']==MAX_RECORDS
            before_reply_bytes=c.received_bytes
            exported=c.rpc(0,{'op':'export'})['events']
            export_reply_bytes=c.received_bytes-before_reply_bytes
            assert len(exported)==MAX_RECORDS and export_reply_bytes<=MAX_REPLY_WIRE
            f.write(json.dumps({'node':0,'request':{'op':'export'},
                                'response_summary':{'records':len(exported),'wire_bytes':export_reply_bytes}})+'\n')
            results.append({'case':'full-store-export-envelope','records':len(exported),
                            'reply_wire_bytes':export_reply_bytes,'reply_limit_bytes':MAX_REPLY_WIRE})
            q={'op':'use','clock':4,'cap':tokens[0]['id'],'actor':1,'right':1,'service':'svc0'}
            assert rpc(0,q)['allow']
            results.append({'case':'full-store-revocation-admission','records':MAX_RECORDS,'new_revocation_refused':True,
                            'receipt_returned':False,'existing_authority_remains_usable_before_expiry':True})
            q.pop('clock')
            try: rpc(0,q)
            except ValueError as e: assert 'clock required' in str(e)
            else: raise AssertionError('implicit clock accepted')
            results.append({'case':'security-rpc-explicit-clock','rejected_missing':True})
            try:
                rpc(0,{'op':'use','clock':MAX_TIME+1,'cap':tokens[0]['id'],'actor':1,'right':1,'service':'svc0'})
            except ValueError as e:
                assert 'clock' in str(e)
            else:
                raise AssertionError('out-of-model clock accepted')
            results.append({'case':'bounded-clock-domain','maximum_clock':MAX_TIME,'oversized_rejected':True})

            legal_max=grant(0,1,None,(1<<32)-1,[MAX_TIME]*5,'n'*128)
            legal_revoke=revocation(legal_max)
            assert shape(legal_max) and typed(legal_max) and len(packed(legal_max))<=MAX_GRANT_WIRE
            assert shape(legal_revoke) and typed(legal_revoke) and len(packed(legal_revoke))<=MAX_EVENT_WIRE
            escaped=grant(0,1,None,1,[1000]*5,'\x00'*128)
            assert len(escaped['nonce'])==128 and len(packed(escaped))>MAX_GRANT_WIRE
            assert not shape(escaped) and not typed(escaped)
            try:
                rpc(0,{'op':'ingest','clock':5,'events':[escaped]})
            except ValueError as e:
                assert 'invalid authenticated event' in str(e)
            else:
                raise AssertionError('oversized encoded record admitted')
            conservative_set_bytes=MAX_RECORDS*(MAX_EVENT_WIRE+1)+2
            assert conservative_set_bytes+MAX_REPLY_OVERHEAD<=MAX_REPLY_WIRE
            results.append({'case':'record-to-reply-wire-envelope',
                            'maximum_grant_bytes':MAX_GRANT_WIRE,
                            'maximum_event_bytes':MAX_EVENT_WIRE,
                            'maximum_reply_bytes':MAX_REPLY_WIRE,
                            'reply_overhead_reserve_bytes':MAX_REPLY_OVERHEAD,
                            'conservative_event_array_bytes':conservative_set_bytes,
                            'escaped_nonce_record_rejected':True})
            delegate_root=grant(1,2,None,7,[1000]*5,'delegation-actor-boundary')
            rpc(2,{'op':'ingest','clock':10,'events':[delegate_root]})
            base={'op':'delegate','parent':delegate_root['id'],'subject':3,'rights':1,
                  'deadlines':delegate_root['deadlines'],'nonce':'delegation-actor-child','clock':11}
            try: rpc(2,base)
            except ValueError as e: assert 'KeyError' in str(e) and 'actor' in str(e)
            else: raise AssertionError('delegate accepted an omitted actor')
            wrong=rpc(2,dict(base,actor=3,nonce='delegation-wrong-actor'))
            assert not wrong['issued'] and wrong['reason']=='subject'
            allowed=rpc(2,dict(base,actor=delegate_root['subject']))
            assert allowed['issued'] and allowed['event']['issuer']==delegate_root['subject']
            results.append({'case':'delegation-explicit-actor','missing_actor_rejected':True,
                            'wrong_actor_rejected':True,'wrong_actor_reason':wrong['reason'],
                            'authorized_actor_issued':True})
            root=grant(0,1,None,7,[1000,1000,1000,200,200],'floor-audiences')
            rr=revocation(root)
            rpc(4,{'op':'ingest','clock':10,'events':[root,rr]})
            at200=rpc(4,{'op':'compact','clock':200})
            assert at200['after']==2
            at1000=rpc(4,{'op':'compact','clock':1000})
            assert at1000['after']==0
            assert rpc(4,{'op':'ingest','clock':1001,'events':[root,rr]})['dropped']==2
            results.append({'case':'global-horizon-not-local-expiry','records_at_200':2,'records_at_1000':0,'replays_dropped':2})
            parent=None; chain=[]
            for j in range(257):
                issuer=0 if parent is None else parent['subject']
                parent=grant(issuer,(issuer+1)%5,parent,7,[10000]*5,'chain-%d'%j);chain.append(parent)
            rpc(1,{'op':'ingest','clock':10,'events':chain})
            for size in [256,257]:
                leaf=chain[size-1]
                d=rpc(1,{'op':'use','clock':11,'cap':leaf['id'],'actor':leaf['subject'],'right':1,'service':'svc0','snapshot':True})
                assert verify_decision(d)
                assert d['allow']==(size==256)
                results.append({'case':'chain-bound','length':size,'allow':d['allow'],'reason':d['reason']})
            parent_255=chain[254]
            issued_256=rpc(1,{'op':'delegate','clock':12,'parent':parent_255['id'],
                              'actor':parent_255['subject'],'subject':4,'rights':1,
                              'deadlines':[9999]*5,'nonce':'chain-issued-256'})
            assert issued_256['issued']
            parent_256=chain[255]
            refused_257=rpc(1,{'op':'delegate','clock':12,'parent':parent_256['id'],
                               'actor':parent_256['subject'],'subject':4,'rights':1,
                               'deadlines':[9999]*5,'nonce':'chain-refused-257'})
            assert not refused_257['issued'] and refused_257['reason']=='chain_limit'
            results.append({'case':'delegation-chain-bound','length_256_issued':True,
                            'length_257_refused':True,'refusal_reason':refused_257['reason']})

            # Two local RPCs may arrive together, but the serial event-loop state
            # transition must be equivalent to one of the two legal orderings.
            # If delegation wins, the subsequent ancestor revoke still blocks the
            # child; if revoke wins, delegation is refused.  No interleaving may
            # leave a usable child after both replies.
            def concurrent_rpc(node,q):
                raw=packed(q)+b'\n'
                with socket.create_connection(('127.0.0.1',c.ports[node]),timeout=10) as s:
                    s.sendall(raw)
                    with s.makefile('rb') as stream:
                        data=stream.readline(MAX_REPLY_WIRE+1)
                if not data or len(data)>MAX_REPLY_WIRE or not data.endswith(b'\n'):
                    raise AssertionError('concurrent reply envelope')
                decoded=json.loads(data)
                if not decoded.get('ok'):
                    raise ValueError(decoded.get('error'))
                return decoded['value'],len(raw),len(data)

            race_issued=race_refused=post_race_allowed=0
            race_rounds=16
            for race in range(race_rounds):
                race_root=grant(0,1,None,7,[10000]*5,'local-race-root-%d'%race)
                rpc(3,{'op':'ingest','clock':50,'events':[race_root]})
                race_revoke=revocation(race_root)
                child_nonce='local-race-child-%d'%race
                delegate_q={'op':'delegate','clock':51,'parent':race_root['id'],
                            'actor':race_root['subject'],'subject':2,'rights':1,
                            'deadlines':[9999]*5,'nonce':child_nonce}
                # The child identifier is deterministic even when the revoke wins
                # and the service refuses to install it.  Querying that identifier
                # in both outcomes keeps the RPC trace and evidence accounting
                # independent of thread scheduling.
                expected_child=grant(race_root['subject'],2,race_root,1,[9999]*5,child_nonce)
                revoke_q={'op':'ingest','clock':51,'events':[race_revoke]}
                with ThreadPoolExecutor(max_workers=2) as executor:
                    delegate_future=executor.submit(concurrent_rpc,3,delegate_q)
                    revoke_future=executor.submit(concurrent_rpc,3,revoke_q)
                    delegate_result,delegate_sent,delegate_received=delegate_future.result()
                    revoke_result,revoke_sent,revoke_received=revoke_future.result()
                c.messages+=2
                c.sent_bytes+=delegate_sent+revoke_sent
                c.received_bytes+=delegate_received+revoke_received
                for value in (delegate_result,revoke_result):
                    c.last_server_cpu_s=max(c.last_server_cpu_s,value['server_cpu_s'])
                    c.max_server_rss_kib=max(c.max_server_rss_kib,value['server_peak_rss_kib'])
                assert len(revoke_result['receipts'])==1
                if delegate_result['issued']:
                    race_issued+=1
                    assert delegate_result['event']['id']==expected_child['id']
                    expected_child_reason='revoked'
                else:
                    race_refused+=1
                    assert delegate_result['reason']=='revoked'
                    expected_child_reason='missing'
                child_decision=rpc(3,{'op':'use','clock':52,'cap':expected_child['id'],
                                      'actor':expected_child['subject'],'right':1,
                                      'service':expected_child['service'],'snapshot':True})
                assert verify_decision(child_decision) and not child_decision['allow']
                assert child_decision['reason']==expected_child_reason
                post_race_allowed+=int(child_decision['allow'])
                root_decision=rpc(3,{'op':'use','clock':52,'cap':race_root['id'],
                                    'actor':race_root['subject'],'right':1,
                                    'service':race_root['service'],'snapshot':True})
                assert verify_decision(root_decision) and not root_decision['allow']
                assert root_decision['reason']=='revoked'
                f.write(json.dumps({'case':'local-delegate-revoke-race','round':race,
                                    'delegate':{'issued':delegate_result['issued'],
                                                'reason':delegate_result['reason']},
                                    'child_reason':child_decision['reason'],
                                    'root_reason':root_decision['reason']})+'\n')
            assert race_issued+race_refused==race_rounds and post_race_allowed==0
            results.append({'case':'local-delegate-revoke-serialization',
                            'rounds':race_rounds,
                            'usable_children_after_both_operations':post_race_allowed,
                            'all_outcomes_match_a_serial_order':True})
            messages=c.messages; wire=c.sent_bytes+c.received_bytes; rss=c.max_server_rss_kib
    target=grant(0,1,None,7,[100]*5,'receipt-target');r=revocation(target)
    other=revocation(grant(0,1,None,7,[100]*5,'other-target'))
    rs=[receipt(i,r) for i in range(4)]+[receipt(4,other)]
    assert not barrier(r,rs,20,0)['closed']
    rs[-1]=receipt(4,r);assert barrier(r,rs,20,0)['closed']
    rs[-1]['mac']='0'*64;assert not barrier(r,rs,20,0)['closed']
    forged_body={'kind':'receipt','gateway':4,'revocation':r['id'],'target':r['target']['id']}
    forged=dict(forged_body,id=hashlib.sha256(packed(forged_body)).hexdigest())
    forged['mac']=hmac.new(PRINCIPAL_KEYS[4],packed(forged),hashlib.sha256).hexdigest()
    assert not receipt_authenticated(forged)
    assert not barrier(r,[*rs[:4],forged],20,0)['closed']
    results.append({'case':'receipt-exact-target-and-authentication','wrong_target_open':True,
                    'corrupt_open':True,'principal_domain_forgery_open':True,
                    'gateway_signer_domain_required':True})
    for bad_clock,bad_epsilon in ((MAX_TIME+1,0),(0,MAX_TIME+1)):
        try: barrier(r,[],bad_clock,bad_epsilon)
        except ValueError: pass
        else: raise AssertionError('out-of-model barrier time accepted')
    # Permanently unusable small deadlines show why the converse needs a qualification.
    tiny=grant(0,1,None,7,[1]*5,'tiny-deadline');tr=revocation(tiny)
    assert not barrier(tr,[],0,2)['closed']
    assert 0+2>=1
    results.append({'case':'converse-degenerate-deadline','certificate_open':True,'minimum_authorizer_upper':2,'deadline':1})
    child=resource.getrusage(resource.RUSAGE_CHILDREN)
    result={'cases':results,'messages':messages,'wire_bytes':wire,'server_peak_rss_kib':rss,
            'wall_s':time.perf_counter()-start,'parent_cpu_s':time.process_time()-cpu,
            'children_cpu_s':child.ru_utime+child.ru_stime,
            'parent_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    (out/'boundaries.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,default=Path('results'))
    args=parser.parse_args()
    print(json.dumps(run(args.out),indent=2))
