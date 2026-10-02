"""Derive tables from recorded, owned-emulator measurements; no new experiments."""
from __future__ import annotations
import argparse,csv,json,statistics
from collections import Counter
from pathlib import Path

SEEDS=(101,211,307,401,503,601,701,809)
def read(path):
    return json.loads(path.read_text())
def write_csv(path, rows):
    if not rows: raise ValueError('no rows')
    with path.open('w',newline='') as stream:
        w=csv.DictWriter(stream,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def summarize(directory: Path):
    d=directory; histories=[read(d/f'history-{s}.json') for s in SEEDS]
    scales=[read(d/f'scale-{n}-{depth}-{seed}.json') for n in (100,1000,5000,10000) for depth in (1,4,16,64) for seed in (17,29,43)]
    finite=read(d/'finite.json'); policies=read(d/'policies.json'); boundaries=read(d/'boundaries.json')
    crashes=read(d/'crashes.json'); differential=read(d/'differential-audit.json')
    closure=read(d/'closure-descendants.json')
    reasons=Counter()
    for x in histories: reasons.update(x['reason_counts'])
    for x in scales:
        raw=list(csv.DictReader((d/f"scale-{x['records']}-{x['depth']}-{x['seed']}.csv").open()))
        assert len(raw)==200
        for metric in ('rpc','service','verifier'):
            values=sorted(int(r[metric+'_ns']) for r in raw)
            for label,p in (('median',.5),('p95',.95),('p99',.99)):
                assert x[metric+'_'+label+'_us']==values[int(p*(len(values)-1))]/1000
    table=[]
    for n in (100,1000,5000,10000):
        for depth in (1,4,16,64):
            group=[x for x in scales if x['records']==n and x['depth']==depth]
            row={'records':n,'depth':depth,'runs':len(group)}
            for m in ('rpc_median_us','service_median_us','verifier_median_us','rpc_p95_us'):
                vals=[x[m] for x in group]
                row[m]=statistics.median(vals);row[m+'_min']=min(vals);row[m+'_max']=max(vals)
            row['logical_json_bytes']=statistics.median(x['logical_json_bytes'] for x in group)
            row['allocated_sqlite_bytes']=statistics.median(x['allocated_sqlite_bytes'] for x in group)
            table.append(row)
    write_csv(d/'scale-summary.csv',table)
    write_csv(d/'history-summary.csv',[{k:x[k] for k in ('seed','epsilon','all_use_checks','closed_certificates','post_barrier_use_checks','messages','wire_bytes','rpc_median_us','rpc_p95_us','wall_s')} for x in histories])
    policy_rows=[]
    for x in policies['policies']:
        obs=next(o for o in x['observations'] if o['tick']==200)
        policy_rows.append({'policy':x['policy'],'closure_delay_ms':x['logical_completion_delay'],
           'unrevoked_available_at_200':sum(z['allow'] for z in obs['unrevoked']),
           'target_available_at_200':sum(z['allow'] for z in obs['target'])})
    write_csv(d/'policy-summary.csv',policy_rows)
    cpu_records=[finite,read(d/'pilot.json'),crashes,policies,boundaries,differential,closure,*histories,*scales]
    out={'finite':{k:v for k,v in finite.items() if not k.endswith(('_s','_kib'))},
         'history':{'seeds':8,'generated_records':sum(x['logical_generated_events'] for x in histories),
             'scheduled_use_requests':sum(x['scheduled_use_requests'] for x in histories),
             'all_use_checks':sum(x['all_use_checks'] for x in histories),
             'closed_certificates':sum(x['closed_certificates'] for x in histories),
             'barrier_checks':sum(x['barrier_checks'] for x in histories),
             'post_barrier_use_checks':sum(x['post_barrier_use_checks'] for x in histories),
             'messages':sum(x['messages'] for x in histories),
             'wire_bytes':sum(x['wire_bytes'] for x in histories),
             'process_restarts':sum(x['process_restarts'] for x in histories),'reasons':dict(reasons)},
         'differential_audit':{'scenarios':differential['scenarios'],'decisions':differential['decisions'],
             'verifier_mismatches':differential['verifier_mismatches'],
             'stateful_replay_audit':differential['stateful_replay_audit'],
             'total_differential_decisions':differential['decisions']+differential['stateful_replay_audit']['decisions'],
             'durable_floor_receipt_case':differential['durable_floor_receipt_case'],
             'scope':differential['scope']},
         'authorization_correspondence':{
             'finite_product_decisions':finite['local_decisions'],
             'static_differential_decisions':differential['decisions'],
             'stateful_replay_decisions':differential['stateful_replay_audit']['decisions'],
             'hidden_descendant_decisions':closure['post_closure_authorization_comparisons'],
             'total':finite['local_decisions']+differential['decisions']+differential['stateful_replay_audit']['decisions']+closure['post_closure_authorization_comparisons'],
             'observed_mismatches':differential['verifier_mismatches']+differential['stateful_replay_audit']['verifier_mismatches']+differential['stateful_replay_audit']['retained_state_mismatches']},
         'crash_recovery':{
             'transaction_crash_cases':crashes['transaction_crash_cases'],
             'sqlite_integrity_checks':crashes['sqlite_integrity_checks'],
             'offline_delegation_cases':crashes['offline_delegation_cases'],
             'scope':crashes['boundary']},
         'closure_descendants':{
             'certificate_closed':closure['certificate_closed'],
             'cover':closure['cover'],
             'hidden_lineage_depth':closure['hidden_lineage_depth'],
             'process_restarts':closure['process_restarts'],
             'authorization_comparisons':closure['post_closure_authorization_comparisons'],
             'delegation_attempts':closure['post_closure_delegation_attempts'],
             'all_authorizations_rejected':closure['all_authorizations_rejected'],
             'all_delegations_rejected':closure['all_delegations_rejected'],
             'scope':closure['scope']},
         'scaling':{'runs':len(scales),'measured_queries':sum(x['measured_queries'] for x in scales),
             'warmup_queries':sum(x['warmup_queries'] for x in scales),
             'generated_records':sum(x['records'] for x in scales)},
         'policies':policy_rows,
         'resources':{'reported_experiment_parent_plus_children_cpu_s':sum(x.get('parent_cpu_s',0)+x.get('children_cpu_s',0) for x in cpu_records),
             'reported_experiment_wall_s_sum':sum(x.get('wall_s',0) for x in cpu_records),
             'largest_reported_parent_rss_kib':max(x.get('parent_peak_rss_kib',0) for x in cpu_records),
             'largest_reported_server_rss_kib':max(x.get('server_peak_rss_kib',0) for x in cpu_records),
             'accounting_scope':'Current per-experiment reports only; excludes earlier development, offline replay, summary, compilation and packaging. RSS maxima are not simultaneous whole-cgroup measurements.'}}
    (d/'summary.json').write_text(json.dumps(out,indent=2)+'\n');return out
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,default=Path('results'));a=p.parse_args()
    print(json.dumps(summarize(a.directory),indent=2))
