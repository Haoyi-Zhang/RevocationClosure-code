"""Bounded subprocess lifecycle and sequential real TCP RPC for the emulator."""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from capability import packed, MAX_REPLY_WIRE

class Cluster:
    def __init__(self,directory,epsilon=0,mode='closed'):
        self.directory=Path(directory); self.epsilon=epsilon; self.mode=mode
        self.messages=0; self.sent_bytes=0; self.received_bytes=0
        self.max_server_rss_kib=0; self.last_server_cpu_s=0; self.previous_server_cpu_s=0
        self.start()
    def start(self):
        self.p=subprocess.Popen([sys.executable,str(Path(__file__).with_name('server.py')),
            '--directory',str(self.directory),'--epsilon',str(self.epsilon),'--mode',self.mode],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        import selectors
        sel=selectors.DefaultSelector(); sel.register(self.p.stdout,selectors.EVENT_READ)
        try:
            if not sel.select(10): self.p.kill(); self.p.wait(); raise RuntimeError('startup timeout')
            line=self.p.stdout.readline()
        finally: sel.close()
        if not line: raise RuntimeError('server startup failed: '+self.p.stderr.read())
        self.ports=json.loads(line)['ports']; self.last_server_cpu_s=0
    def rpc(self,node,q):
        raw=packed(q)+b'\n'; self.messages+=1; self.sent_bytes+=len(raw)
        start=time.perf_counter_ns()
        with socket.create_connection(('127.0.0.1',self.ports[node]),timeout=10) as s:
            s.sendall(raw)
            with s.makefile('rb') as f: data=f.readline(MAX_REPLY_WIRE+1)
        if not data: raise ConnectionError('server stopped before reply')
        if len(data)>MAX_REPLY_WIRE or not data.endswith(b'\n'):
            raise ValueError('reply limit or truncated reply')
        self.received_bytes+=len(data)
        out=json.loads(data)
        if not out.get('ok'): raise ValueError(out.get('error'))
        v=out['value']; v['rpc_ns']=time.perf_counter_ns()-start
        self.last_server_cpu_s=max(self.last_server_cpu_s,v['server_cpu_s'])
        self.max_server_rss_kib=max(self.max_server_rss_kib,v['server_peak_rss_kib'])
        return v
    def restart(self):
        self.close(); self.start()
    def close(self):
        if self.p is not None:
            self.previous_server_cpu_s+=self.last_server_cpu_s
            if self.p.poll() is None: self.p.terminate()
            try: self.p.wait(timeout=5)
            except subprocess.TimeoutExpired: self.p.kill(); self.p.wait()
            self.p.stdout.close(); self.p.stderr.close(); self.p=None
    def __enter__(self): return self
    def __exit__(self,*args): self.close()
