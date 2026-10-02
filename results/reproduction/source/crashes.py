"""Actual owned process crashes at transaction boundaries and scoped ablations."""
import argparse,json,resource,sqlite3,tempfile,time
from pathlib import Path
from capability import grant,revocation
from transport import Cluster
from verifier import verify_decision

def use(c,node,g,clock,snapshot=True):
    return c.rpc(node,{'op':'use','cap':g['id'],'actor':g['subject'],'right':1,'service':g['service'],'clock':clock,'snapshot':snapshot})

def database_integrity(directory):
    checked=0
    for path in sorted(Path(directory).glob('*.sqlite')):
        with sqlite3.connect(path) as connection:
            row=connection.execute('PRAGMA integrity_check').fetchone()
        assert row == ('ok',), (path,row)
        checked += 1
    assert checked == 5, (directory,checked)
    return checked

def run(out):
    out.mkdir(parents=True,exist_ok=True);started=time.perf_counter();cpu=time.process_time()
    old=resource.getrusage(resource.RUSAGE_CHILDREN);traces=[];messages=wire=0;rss=0;integrity_checks=0
    root=grant(0,1,None,7,[1000,1000,1000,200,200],'fault-root')
    child=grant(1,2,root,3,root['deadlines'],'fault-child');rev=revocation(root)
    with tempfile.TemporaryDirectory() as tmp:
        for point in ('before_transaction','before_commit','after_commit_before_reply','after_reply'):
            directory=Path(tmp)/('ingest-'+point)
            with Cluster(directory) as c:
                c.rpc(0,{'op':'ingest','events':[root,child],'clock':10})
                got_receipt=False;lost_reply=False
                if point=='after_reply':
                    got_receipt=bool(c.rpc(0,{'op':'ingest','events':[rev],'clock':20})['receipts'])
                else:
                    try:c.rpc(0,{'op':'ingest','events':[rev],'clock':20,'failpoint':point})
                    except ConnectionError:lost_reply=True
                    else:raise AssertionError('fault did not stop process')
                c.restart();d=use(c,0,child,21);assert verify_decision(d)
                expected='revoked' if point in ('after_commit_before_reply','after_reply') else 'allow'
                assert d['reason']==expected
                traces.append({'operation':'revoke','point':point,'receipt_received':got_receipt,'reply_lost':lost_reply,'decision':d})
                messages+=c.messages;wire+=c.sent_bytes+c.received_bytes;rss=max(rss,c.max_server_rss_kib)
            integrity_checks += database_integrity(directory)
        for point in ('before_transaction','before_floor','before_commit','after_commit_before_reply','after_reply'):
            directory=Path(tmp)/('compact-'+point)
            with Cluster(directory) as c:
                c.rpc(0,{'op':'ingest','events':[root,child,rev],'clock':20})
                if point=='after_reply': c.rpc(0,{'op':'compact','clock':1000})
                else:
                    try:c.rpc(0,{'op':'compact','clock':1000,'failpoint':point})
                    except ConnectionError:pass
                    else:raise AssertionError('fault did not stop process')
                c.restart();s=c.rpc(0,{'op':'stats','clock':1001})
                committed=point in ('after_commit_before_reply','after_reply')
                assert (s['floor'],s['records'])==((1000,0) if committed else (0,3))
                replay=c.rpc(0,{'op':'ingest','events':[root,child,rev],'clock':1001})
                d=use(c,0,child,1001);assert not d['allow'] and verify_decision(d)
                if committed:assert replay['added']==0 and replay['dropped']==3
                traces.append({'operation':'compact','point':point,'state_after_restart':s,'replay':replay,'decision':d})
                messages+=c.messages;wire+=c.sent_bytes+c.received_bytes;rss=max(rss,c.max_server_rss_kib)
            integrity_checks += database_integrity(directory)
        # A real local delegation while its gateway is disconnected from the revoke.
        with Cluster(Path(tmp)/'offline-delegate') as c:
            for i in range(5):c.rpc(i,{'op':'ingest','events':[root],'clock':10})
            c.rpc(0,{'op':'ingest','events':[rev],'clock':20})
            issued=c.rpc(4,{'op':'delegate','parent':root['id'],'actor':root['subject'],'subject':2,'rights':1,'deadlines':root['deadlines'],'nonce':'offline-created','clock':30})
            assert issued['issued'];g=issued['event'];before=use(c,4,g,31);assert before['allow'] and verify_decision(before)
            denied_issue=c.rpc(0,{'op':'delegate','parent':root['id'],'actor':root['subject'],'subject':2,'rights':1,'deadlines':root['deadlines'],'nonce':'connected-denied','clock':30})
            assert not denied_issue['issued'] and denied_issue['reason']=='revoked'
            c.rpc(0,{'op':'ingest','events':[g],'clock':35});known=use(c,0,g,35)
            c.rpc(4,{'op':'ingest','events':[rev],'clock':40});after=use(c,4,g,40)
            assert known['reason']==after['reason']=='revoked';assert verify_decision(known) and verify_decision(after)
            traces.append({'operation':'offline-delegation','issuer_result':issued,'before_delivery':before,'after_delivery':after,'connected_issue':denied_issue})
            messages+=c.messages;wire+=c.sent_bytes+c.received_bytes;rss=max(rss,c.max_server_rss_kib)
        ablations=[]
        for mode in ('closed','volatile','leaf-only','lww'):
            with Cluster(Path(tmp)/mode,mode=mode) as c:
                c.rpc(0,{'op':'ingest','events':[root,child],'clock':10})
                c.rpc(0,{'op':'ingest','events':[rev],'clock':20})
                if mode=='volatile':c.restart()
                if mode=='lww':c.rpc(0,{'op':'ingest','events':[root],'clock':30})
                d=use(c,0,child,31,False)
                assert d['allow']==(mode!='closed')
                ablations.append({'mode':mode,'allow':d['allow'],'reason':d['reason'],'failure_type':'none' if mode=='closed' else 'pre-expiry-revoked-use'})
                messages+=c.messages;wire+=c.sent_bytes+c.received_bytes;rss=max(rss,c.max_server_rss_kib)
        for mode in ('closed','clock-unsafe'):
            g=grant(0,1,None,1,[100]*5,'clock')
            with Cluster(Path(tmp)/('clock-'+mode),epsilon=10,mode=mode) as c:
                c.rpc(0,{'op':'ingest','events':[g],'clock':90})
                d=use(c,0,g,90,False);assert d['allow']==(mode=='clock-unsafe')
                ablations.append({'mode':mode,'actual_time':100,'clock':90,'epsilon':10,'deadline':100,'allow':d['allow'],'failure_type':'none' if mode=='closed' else 'expired-use'})
                messages+=c.messages;wire+=c.sent_bytes+c.received_bytes;rss=max(rss,c.max_server_rss_kib)
        for mode in ('closed','no-floor'):
            gs=[grant(0,1,None,1,[100]*5,'expired-'+str(i)) for i in range(1000)]
            with Cluster(Path(tmp)/('gc-'+mode),mode=mode) as c:
                c.rpc(0,{'op':'ingest','events':gs,'clock':10});before=c.rpc(0,{'op':'stats'})
                c.rpc(0,{'op':'compact','clock':100});c.restart()
                replay=c.rpc(0,{'op':'ingest','events':gs,'clock':101});after=c.rpc(0,{'op':'stats'})
                d=use(c,0,gs[0],101,False);assert not d['allow']
                assert after['records']==(1000 if mode=='no-floor' else 0)
                ablations.append({'mode':mode,'before':before,'after':after,'replay_added':replay['added'],'allow':d['allow'],'failure_type':'none' if mode=='closed' else 'metadata-reappearance-only'})
                messages+=c.messages;wire+=c.sent_bytes+c.received_bytes;rss=max(rss,c.max_server_rss_kib)
    new=resource.getrusage(resource.RUSAGE_CHILDREN)
    result={'transaction_crash_cases':9,'sqlite_integrity_checks':integrity_checks,'offline_delegation_cases':1,'ablations':ablations,'traces':traces,
            'messages':messages,'wire_bytes':wire,'server_peak_rss_kib':rss,'wall_s':time.perf_counter()-started,
            'parent_cpu_s':time.process_time()-cpu,'children_cpu_s':new.ru_utime+new.ru_stime-old.ru_utime-old.ru_stime,
            'parent_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'boundary':'Actual process termination; all five endpoints share one process. No machine/power-loss claim.'}
    (out/'crashes.json').write_text(json.dumps(result,indent=2)+'\n');return {k:v for k,v in result.items() if k not in ('traces','ablations')}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=Path('results'));a=p.parse_args();print(json.dumps(run(a.out),indent=2))
