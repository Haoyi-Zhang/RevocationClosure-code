"""Independent feasible-time oracle and owned-process collector crash tests."""
from __future__ import annotations
import argparse,copy,itertools,json,resource,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from collector import ClosureJournal,advance_lower_bound,coverage
from capability import Store,grant,revocation,receipt,barrier,sign

def possible_now(history,epsilon):
    reachable={0}
    for c in history:
        reachable={t for t in range(11) if abs(c-t)<=epsilon and any(p<=t for p in reachable)}
    return {t for t in range(11) if any(p<=t for p in reachable)}

def run(out):
    began=time.perf_counter();cpu=time.process_time()
    count=closed=opens=histories=invalid=improvements=0;witnesses=[]
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        for eps in (0,1,2):
            hs=[()]+[(c,) for c in range(7)]+list(itertools.product(range(7),repeat=2))
            for hist in hs:
                times=possible_now(hist,eps)
                if not times:
                    invalid+=1
                    try:
                        k=0
                        for c in hist:k=advance_lower_bound(k,c,eps)
                    except ValueError:pass
                    else:raise AssertionError('inconsistent history accepted')
                    continue
                histories+=1;k=0
                for c in hist:k=advance_lower_bound(k,c,eps)
                assert min(times)==k
                can_use={d:any(c+eps<d for t in times for c in range(13) if abs(c-t)<=eps) for d in range(7)}
                for d0,d1,mask in itertools.product(range(7),range(7),range(4)):
                    ds=[d0,d1,0,0,0]
                    expected=all(mask&(1<<i) or not can_use[d] for i,d in enumerate(ds[:2]))
                    got=coverage(ds,mask,k,eps);assert got['closed']==expected
                    count+=1;closed+=expected;opens+=not expected
                    if hist:
                        legacy=all(mask&(1<<i) or hist[-1]-eps>=d for i,d in enumerate(ds))
                        improvements+=bool(expected and not legacy)
                    if not expected:
                        w=got['uncovered_witness']
                        assert w['possible_actual_time'] in times
                        assert abs(w['possible_gateway_clock']-w['possible_actual_time'])<=eps
                        assert w['gateway_upper_bound']<w['target_deadline']
                        if len(witnesses)<96 and count%97==0:witnesses.append((eps,ds,w))
        for idx,(eps,ds,w) in enumerate(witnesses):
            g=grant(0,1,None,1,ds,f'witness-{idx}');s=Store(root/f'w{idx}.sqlite',w['gateway'],eps)
            s.set_clock(w['possible_gateway_clock']);s.ingest([g])
            assert s.authorize(g['id'],1,1,'svc0')['allow'];s.close()
        g=grant(0,1,None,1,[10]*5,'regression');r=revocation(g);p=root/'regression.sqlite'
        with ClosureJournal(p,r,2) as j:
            first=j.observe(12,[]);second=j.observe(9,[])
            assert first['closed'] and second['closed']
            assert barrier(r,[],12,2)['closed'] and not barrier(r,[],9,2)['closed']
        with ClosureJournal(p,r,2) as j:
            assert j.status()==second
            try:j.observe(0,[])
            except ValueError:pass
            else:raise AssertionError('contradictory clock accepted')
            assert j.status()==second
        g2=grant(0,1,None,1,[100]*5,'binding');r2=revocation(g2);p2=root/'binding.sqlite';rejected=0
        with ClosureJournal(p2,r2,2) as j:
            rs=[receipt(i,r2) for i in range(5)];j.observe(3,[rs[0]]);before=j.status()
            bad=copy.deepcopy(rs[1]);bad['mac']='0'*64
            forged=sign({'kind':'receipt','issuer':1,'gateway':1,'revocation':r2['id'],'target':g2['id']})
            for incoming in ([rs[1],bad],[receipt(1,r)],[forged],[rs[1]]*11):
                try:j.observe(4,incoming)
                except ValueError:rejected+=1
                else:raise AssertionError('invalid batch accepted')
                assert j.status()==before
            done=j.observe(4,rs);assert done['closed'] and j.observe(4,rs)==done
        for other,eps in ((r,2),(r2,1)):
            try:ClosureJournal(p2,other,eps)
            except ValueError:rejected+=1
            else:raise AssertionError('configuration rebound')
        faults=[]
        for point in ('before_transaction','before_commit','after_commit_before_reply'):
            path=root/f'{point}.sqlite'
            with ClosureJournal(path,r2,2) as j:j.observe(2,[receipt(0,r2)]);old=j.status()
            q=root/f'{point}.json';q.write_text(json.dumps(dict(path=str(path),r=r2,point=point)))
            cp=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--fault',str(q)],capture_output=True,text=True,timeout=20)
            assert cp.returncode==70,cp.stderr
            with ClosureJournal(path,r2,2) as j:
                got=j.status();assert got['closed']==(point=='after_commit_before_reply')
                if point!='after_commit_before_reply':assert got==old
                assert j.db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
                faults.append(dict(point=point,exit=70,closed_after_reopen=got['closed'],integrity='ok'))
        result=dict(finite_comparisons=count,closed_cases=closed,open_witness_cases=opens,
                    feasible_histories=histories,inconsistent_histories_rejected=invalid,
                    additional_closed_cases=improvements,sql_witness_checks=len(witnesses),
                    rejected_binding_cases=rejected,legacy_status=[True,False],journal_status=[True,True,True],
                    crash_cases=faults,mismatches=0,wall_s=time.perf_counter()-began,
                    parent_cpu_s=time.process_time()-cpu,parent_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    out.mkdir(parents=True,exist_ok=True);(out/'collector-audit.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
    if not __debug__:raise RuntimeError('Do not use -O')
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=Path('results'));p.add_argument('--fault',type=Path);a=p.parse_args()
    if a.fault:
        q=json.loads(a.fault.read_text())
        with ClosureJournal(Path(q['path']),q['r'],2) as j:j.observe(5,[receipt(i,q['r']) for i in range(5)],q['point'])
        raise SystemExit('fault did not fire')
    print(json.dumps(run(a.out),indent=2))
