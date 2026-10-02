"""Separate replay decision evaluator. Does not import capability or server.

A supplied complete LOCAL snapshot is an assumption, not an authenticated proof
of absence at other gateways. HMAC keys are public fixture keys, with distinct
principal-event and gateway-receipt domains.
"""
import hashlib
import hmac
import json

MAX_TIME = 1 << 53
MAX_GRANT_WIRE = 512
MAX_EVENT_WIRE = 768


def _encoding(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _hex64(value):
    return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)


def _authentic_with(x, signer_field, key_prefix):
    try:
        who=x[signer_field]; sig=x['mac']; ident=x['id']
        if type(who) is not int or not 0<=who<5: return False
        bare=dict(x); del bare['mac']; del bare['id']
        if ident!=hashlib.sha256(_encoding(bare)).hexdigest(): return False
        bare['id']=ident
        key=(key_prefix%who).encode()
        return hmac.compare_digest(sig,hmac.digest(key,_encoding(bare),'sha256').hex())
    except (TypeError,ValueError,KeyError): return False


def authentic_event(x):
    return _authentic_with(x, 'issuer', 'public-toy-key-%d-not-a-credential')


def authentic_receipt(x):
    return _authentic_with(
        x, 'gateway', 'public-toy-gateway-receipt-key-%d-not-a-credential'
    )


def authentic(x):
    if isinstance(x,dict) and x.get('kind')=='receipt': return authentic_receipt(x)
    return authentic_event(x)


def evaluate(snapshot, request, node, clock, epsilon, floor):
    """Root-to-leaf stack validation; SQL-independent dictionary/set oracle."""
    if not all(typed(e) for e in snapshot): raise ValueError('snapshot authentication or shape')
    grants={x['id']:x for x in snapshot if x['kind']=='grant'}
    revoked={x['target']['id'] for x in snapshot if x['kind']=='revoke'}
    return indexed(grants,revoked,request,node,clock,epsilon,floor)


def indexed(grants,revoked,request,node,clock,epsilon,floor):
    ident=request['cap']; path=[]
    while ident is not None:
        if ident in path or len(path)>=256: return ('chain_limit',ident)
        if ident not in grants: return ('missing',ident)
        path.append(ident); ident=grants[ident]['parent']
    leaf=grants[path[0]]
    if leaf['service']!=request['service'] or grants[path[-1]]['service']!='svc'+str(grants[path[-1]]['issuer']): return ('service',path[0])
    if leaf['subject']!=request['actor']: return ('subject',path[0])
    want={b for b in range(32) if request['right'] & (1<<b)}
    have={b for b in range(32) if leaf['rights'] & (1<<b)}
    if not want <= have: return ('right',path[0])
    # Ordered edge tests in reverse path, then select the nearest invalid edge.
    invalid=[]
    lineage=list(reversed(path))
    for parent_id,child_id in zip(lineage,lineage[1:]):
        parent,child=grants[parent_id],grants[child_id]
        child_rights={b for b in range(32) if child['rights']&(1<<b)}
        parent_rights={b for b in range(32) if parent['rights']&(1<<b)}
        if (parent['service']!=child['service'] or parent['subject']!=child['issuer'] or not child_rights<=parent_rights or
            not all(child['deadlines'][k]<=parent['deadlines'][k] for k in range(5))): invalid.append(child_id)
    if invalid: return ('attenuation',invalid[-1])
    blocked=set(path)&revoked
    if blocked: return ('revoked',next(x for x in path if x in blocked))
    expiry=leaf['deadlines'][node]
    if not (expiry>floor and expiry>clock+epsilon): return ('expired',leaf['id'])
    return ('allow',None)


def verify_decision(d):
    reason,atom=evaluate(d['snapshot'],d['request'],d['node'],d['clock'],d['epsilon'],d['floor'])
    return reason==d['reason'] and atom==d['atom'] and d['allow']==(reason=='allow')


def verify_barrier(rev, receipts, clock, epsilon):
    if not typed(rev) or rev.get('kind')!='revoke': return False
    if (type(clock) is not int or type(epsilon) is not int or
            not 0<=clock<=MAX_TIME or not 0<=epsilon<=MAX_TIME): return False
    if rev['issuer']!=rev['target']['issuer']: return False
    required=set(range(5))
    for r in receipts:
        if (authentic_receipt(r) and set(r)=={'kind','gateway','revocation','target','id','mac'} and
            r.get('kind')=='receipt' and r.get('revocation')==rev['id'] and r.get('target')==rev['target']['id']):
            required.discard(r['gateway'])
    return all(rev['target']['deadlines'][i] <= clock-epsilon for i in required)


def typed(e):
    """Independently spelled-out wire record validation, with no service import."""
    if not isinstance(e,dict) or not authentic_event(e): return False
    try: wire_size=len(_encoding(e))
    except (TypeError,ValueError): return False
    if e.get('kind')=='revoke':
        return (wire_size<=MAX_EVENT_WIRE and set(e)=={'kind','issuer','target','id','mac'} and
                isinstance(e['target'],dict) and e['target'].get('kind')=='grant' and
                typed(e['target']) and e['issuer']==e['target']['issuer'])
    if e.get('kind')!='grant' or wire_size>MAX_GRANT_WIRE: return False
    if set(e)!={'kind','issuer','subject','parent','rights','deadlines','nonce','service','id','mac'}: return False
    if type(e['subject']) is not int or e['subject'] not in range(5): return False
    if type(e['rights']) is not int or e['rights'] not in range(1,2**32): return False
    if e['service'] not in tuple('svc'+str(i) for i in range(5)): return False
    if not isinstance(e['nonce'],str) or not 1<=len(e['nonce'])<=128: return False
    if e['parent'] is not None and not _hex64(e['parent']): return False
    return isinstance(e['deadlines'],list) and len(e['deadlines'])==5 and all(type(d) is int and 0<=d<=MAX_TIME for d in e['deadlines'])


class Replay:
    """Incremental complete-local-view replay for measured emulator histories.

    Events are authenticated and type-checked once on input. Authorization is a
    separate set/dictionary path evaluator. This does not certify log completeness.
    """
    def __init__(self,node,epsilon=0):
        if type(node) is not int or node not in range(5) or type(epsilon) is not int or not 0<=epsilon<=MAX_TIME:
            raise ValueError('replay configuration')
        self.node=node; self.epsilon=epsilon; self.floor=0; self.records={}
        self.grants={}; self.revoked=set()
    def ingest(self,events):
        if not all(typed(x) for x in events): raise ValueError('replay record')
        for x in events:
            g=x if x['kind']=='grant' else x['target']
            if any(d>self.floor for d in g['deadlines']): self.records[x['id']]=x
        self._index()
    def _index(self):
        self.grants={k:x for k,x in self.records.items() if x['kind']=='grant'}
        self.revoked={x['target']['id'] for x in self.records.values() if x['kind']=='revoke'}
    def compact(self,clock):
        if type(clock) is not int or not 0<=clock<=MAX_TIME: raise ValueError('replay clock')
        self.floor=max(self.floor,clock-self.epsilon)
        self.records={k:x for k,x in self.records.items() if any(d>self.floor for d in (x if x['kind']=='grant' else x['target'])['deadlines'])}
        self._index()
    def decide(self,request,clock):
        if type(clock) is not int or not 0<=clock<=MAX_TIME: raise ValueError('replay clock')
        return indexed(self.grants,self.revoked,request,self.node,clock,self.epsilon,self.floor)
