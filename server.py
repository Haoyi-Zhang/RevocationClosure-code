"""Five owned localhost endpoints in ONE process; separate durable databases."""
import argparse
import asyncio
import json
import resource
import time
from pathlib import Path
from capability import Store, packed, barrier, MAX_WIRE, MAX_REPLY_WIRE, N

async def main():
    p=argparse.ArgumentParser(); p.add_argument('--directory',required=True)
    p.add_argument('--epsilon',type=int,default=0); p.add_argument('--mode',default='closed')
    a=p.parse_args(); d=Path(a.directory); d.mkdir(parents=True,exist_ok=True)
    resource.setrlimit(resource.RLIMIT_CPU,(180,180))
    resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3))
    stores=[Store(d/('%d.sqlite'%i),i,a.epsilon,a.mode) for i in range(N)]
    async def handle(node,reader,writer):
        try:
            raw=await asyncio.wait_for(reader.readline(),timeout=5)
            if len(raw)>MAX_WIRE: raise ValueError('wire limit')
            q=json.loads(raw); op=q['op']; s=stores[node]; start=time.perf_counter_ns()
            if op in {'ingest','use','delegate','barrier','compact'} and 'clock' not in q:
                raise ValueError('explicit emulator clock required')
            if 'clock' in q: s.set_clock(q['clock'])
            if op=='ingest': out=s.ingest(q['events'],q.get('failpoint'))
            elif op=='use': out=s.authorize(q['cap'],q['actor'],q['right'],q['service'],q.get('snapshot',False))
            elif op=='delegate': out=s.delegate(q['parent'],q['actor'],q['subject'],q['rights'],q['deadlines'],q['nonce'])
            elif op=='export': out={'events':s.events()}
            elif op=='compact': out=s.compact(q.get('failpoint'))
            elif op=='barrier': out=barrier(q['revocation'],q['receipts'],s.clock,s.epsilon,q.get('rule','hybrid'))
            elif op=='stats': out=s.stats()
            elif op=='clock': out={'clock':s.clock}
            else: raise ValueError('operation')
            out['service_ns']=time.perf_counter_ns()-start
            out['server_cpu_s']=time.process_time()
            out['server_peak_rss_kib']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            reply=packed({'ok':True,'value':out})
            if len(reply)+1 > MAX_REPLY_WIRE:
                reply=packed({'ok':False,'error':'ValueError: reply limit'})
            writer.write(reply+b'\n')
        except (ValueError,KeyError,TypeError,TimeoutError,asyncio.LimitOverrunError) as e:
            writer.write(packed({'ok':False,'error':type(e).__name__+': '+str(e)})+b'\n')
        except BaseException as e:
            writer.write(packed({'ok':False,'error':'internal: '+type(e).__name__})+b'\n')
        finally:
            try: await writer.drain()
            except (ConnectionError,BrokenPipeError): pass
            writer.close(); await writer.wait_closed()
    servers=[]
    for i in range(N):
        async def h(r,w,j=i): await handle(j,r,w)
        servers.append(await asyncio.start_server(h,'127.0.0.1',0,limit=MAX_WIRE+1))
    print(json.dumps({'ports':[s.sockets[0].getsockname()[1] for s in servers]}),flush=True)
    try: await asyncio.Event().wait()
    finally:
        for s in servers: s.close(); await s.wait_closed()
        for s in stores: s.close()

if __name__=='__main__': asyncio.run(main())
