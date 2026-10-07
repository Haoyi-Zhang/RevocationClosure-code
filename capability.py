"""Finite offline-delegation model. Synthetic authentication, not credentials.

All clocks are integer logical milliseconds supplied by the owned emulator.
SQLite FULL commits model durable acknowledgements; no filesystem-loss claim.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

N = 5
MAX_RECORDS = 20000
MAX_CHAIN = 256
MAX_WIRE = 4 * 1024 * 1024
MAX_REPLY_WIRE = 16 * 1024 * 1024
MAX_REPLY_OVERHEAD = 1024 * 1024
MAX_GRANT_WIRE = 512
MAX_EVENT_WIRE = 768
MAX_TIME = 1 << 53

# A full legal event set plus response metadata must fit one bounded reply.
if MAX_RECORDS * (MAX_EVENT_WIRE + 1) + MAX_REPLY_OVERHEAD > MAX_REPLY_WIRE:
    raise RuntimeError('record and reply limits are inconsistent')
PRINCIPAL_KEYS = tuple(
    ("public-toy-key-%d-not-a-credential" % i).encode() for i in range(N)
)
GATEWAY_RECEIPT_KEYS = tuple(
    ("public-toy-gateway-receipt-key-%d-not-a-credential" % i).encode()
    for i in range(N)
)


def packed(x: Any) -> bytes:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sign_with_key(body: dict, key: bytes) -> dict:
    b = dict(body)
    b['id'] = hashlib.sha256(packed(body)).hexdigest()
    b['mac'] = hmac.new(key, packed(b), hashlib.sha256).hexdigest()
    return b


def sign(body: dict) -> dict:
    """Sign a grant or revoke in the synthetic principal-event key domain."""
    issuer = body.get('issuer')
    if type(issuer) is not int or not 0 <= issuer < N:
        raise ValueError('issuer')
    return _sign_with_key(body, PRINCIPAL_KEYS[issuer])


def _authenticated_with(e: Any, signer_field: str, keys: tuple[bytes, ...]) -> bool:
    if (not isinstance(e, dict) or type(e.get(signer_field)) is not int or
            not 0 <= e[signer_field] < N):
        return False
    try:
        body = {k: v for k, v in e.items() if k not in ('id', 'mac')}
        with_id = dict(body, id=e['id'])
        return (e['id'] == hashlib.sha256(packed(body)).hexdigest() and
                hmac.compare_digest(
                    e['mac'],
                    hmac.new(keys[e[signer_field]], packed(with_id), hashlib.sha256).hexdigest(),
                ))
    except (KeyError, TypeError, ValueError):
        return False


def event_authenticated(e: Any) -> bool:
    return _authenticated_with(e, 'issuer', PRINCIPAL_KEYS)


def receipt_authenticated(r: Any) -> bool:
    return _authenticated_with(r, 'gateway', GATEWAY_RECEIPT_KEYS)


def authenticated(e: Any) -> bool:
    """Validate a typed fixture signature without merging signer domains."""
    if isinstance(e, dict) and e.get('kind') == 'receipt':
        return receipt_authenticated(e)
    return event_authenticated(e)


def _hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def shape(e: dict) -> bool:
    if not event_authenticated(e):
        return False
    try:
        wire_size = len(packed(e))
    except (TypeError, ValueError):
        return False
    if e.get('kind') == 'grant':
        return (wire_size <= MAX_GRANT_WIRE and
                set(e) == {'kind','issuer','subject','parent','rights','deadlines','nonce','service','id','mac'} and
                isinstance(e['service'], str) and e['service'] in {'svc0','svc1','svc2','svc3','svc4'} and
                type(e['subject']) is int and 0 <= e['subject'] < N and
                (e['parent'] is None or _hex64(e['parent'])) and
                type(e['rights']) is int and 0 < e['rights'] < (1 << 32) and
                isinstance(e['deadlines'], list) and len(e['deadlines']) == N and
                all(type(d) is int and 0 <= d <= MAX_TIME for d in e['deadlines']) and
                isinstance(e['nonce'], str) and 0 < len(e['nonce']) <= 128)
    if e.get('kind') == 'revoke':
        t = e.get('target')
        return (wire_size <= MAX_EVENT_WIRE and
                set(e) == {'kind','issuer','target','id','mac'} and isinstance(t, dict) and
                t.get('kind') == 'grant' and shape(t) and e['issuer'] == t['issuer'])
    return False


def grant(issuer: int, subject: int, parent: dict | None, rights: int, deadlines: list[int], nonce: str) -> dict:
    return sign({'kind':'grant', 'issuer':issuer, 'subject':subject,
                 'parent':None if parent is None else parent['id'], 'rights':rights,
                 'deadlines':deadlines, 'nonce':nonce, 'service':('svc'+str(issuer)) if parent is None else parent['service']})


def revocation(g: dict) -> dict:
    return sign({'kind':'revoke','issuer':g['issuer'],'target':g})


def receipt(node: int, rev: dict) -> dict:
    if type(node) is not int or not 0 <= node < N:
        raise ValueError('gateway')
    return _sign_with_key(
        {'kind':'receipt','gateway':node,'revocation':rev['id'], 'target':rev['target']['id']},
        GATEWAY_RECEIPT_KEYS[node],
    )


def barrier(rev: dict, receipts: list[dict], clock: int, epsilon: int, rule: str = 'hybrid') -> dict:
    """A certificate closes EACH gateway through receipt or inherited deadline."""
    if (not shape(rev) or rev['kind'] != 'revoke' or type(clock) is not int or
            type(epsilon) is not int or not 0 <= clock <= MAX_TIME or not 0 <= epsilon <= MAX_TIME):
        raise ValueError('invalid barrier input')
    got = {r['gateway'] for r in receipts if receipt_authenticated(r) and
           set(r) == {'kind','gateway','revocation','target','id','mac'} and
           r.get('kind') == 'receipt' and r.get('revocation') == rev['id'] and
           r.get('target') == rev['target']['id']}
    cover = ['receipt' if i in got else 'expiry' if clock-epsilon >= d else 'open'
             for i, d in enumerate(rev['target']['deadlines'])]
    if rule=='all-receipts': cover=['receipt' if i in got else 'open' for i in range(N)]
    elif rule=='lease-only': cover=['expiry' if clock-epsilon>=d else 'open' for d in rev['target']['deadlines']]
    elif rule!='hybrid': raise ValueError('barrier rule')
    return {'closed': 'open' not in cover, 'cover':cover, 'lower_time':clock-epsilon}


class Store:
    """Per-gateway durable admission floor and immutable event set.

    The floor is a local durable lower time bound. Garbage collection uses the
    MAXIMUM audience deadline, so a pruned token is unusable at every gateway.
    State equality after time-based compaction requires common normalization.
    """
    def __init__(self, path: Path, node: int, epsilon: int = 0, mode: str = 'closed'):
        if type(node) is not int or not 0 <= node < N or type(epsilon) is not int or not 0 <= epsilon <= MAX_TIME or mode not in {'closed','all-ack','lease','lww','acl','volatile','no-floor','leaf-only','clock-unsafe'}:
            raise ValueError('configuration')
        self.node, self.epsilon, self.mode = node, epsilon, mode
        self.path = Path(path)
        self.db = sqlite3.connect(self.path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT, deadline INTEGER NOT NULL, payload TEXT NOT NULL, stamp INTEGER NOT NULL)')
        self.db.execute('CREATE INDEX IF NOT EXISTS target_idx ON events(target,kind)')
        self.db.execute("INSERT OR IGNORE INTO meta VALUES ('floor',0)")
        self.db.commit()
        self.volatile: dict[str,dict] = {}
        self.clock = 0

    @property
    def floor(self) -> int:
        return int(self.db.execute("SELECT value FROM meta WHERE key='floor'").fetchone()[0])

    def set_clock(self, clock: int) -> None:
        if type(clock) is not int or not 0 <= clock <= MAX_TIME:
            raise ValueError('clock')
        self.clock = clock

    def events(self) -> list[dict]:
        return [json.loads(row[0]) for row in self.db.execute('SELECT payload FROM events ORDER BY id')]

    def _fault(self, point: str, selected: str | None):
        if point == selected:
            os._exit(70)  # kills the owned server process, not a third-party service

    def ingest(self, batch: list[dict], failpoint: str | None = None) -> dict:
        if not isinstance(batch,list) or len(batch) > MAX_RECORDS:
            raise ValueError('batch limit')
        if not all(shape(e) for e in batch):
            raise ValueError('invalid authenticated event')
        added = dropped = 0
        rs = []
        # The volatile baseline deliberately loses revocations on process
        # recovery, but a failed SQLite transaction must still be atomic within
        # the running process.  Stage those in-memory changes until the durable
        # portion of the batch has committed; otherwise a later capacity error
        # could leave a revocation visible even though the whole RPC failed.
        pending_volatile: dict[str, dict] = {}
        self._fault('before_transaction', failpoint)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            count = self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            f = self.floor
            for e in batch:
                g = e if e['kind']=='grant' else e['target']
                d = max(g['deadlines'])
                if e['kind']=='revoke' and self.mode=='volatile':
                    pending_volatile[g['id']] = e
                elif d <= f and self.mode != 'no-floor':
                    dropped += 1
                else:
                    if count >= MAX_RECORDS and self.db.execute('SELECT 1 FROM events WHERE id=?',(e['id'],)).fetchone() is None:
                        raise ValueError('record limit')
                    cur = self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?)',
                        (e['id'], e['kind'], g['id'], d, packed(e).decode(), self.clock))
                    added += cur.rowcount
                    count += cur.rowcount
                    if self.mode == 'lww' and cur.rowcount == 0:
                        self.db.execute('UPDATE events SET stamp=MAX(stamp,?) WHERE id=?',(self.clock,e['id']))
                if e['kind']=='revoke':
                    rs.append(receipt(self.node,e))
            self._fault('before_commit', failpoint)
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        self.volatile.update(pending_volatile)
        self._fault('after_commit_before_reply', failpoint)
        return {'added':added,'dropped':dropped,'receipts':rs}

    def compact(self, failpoint: str | None = None) -> dict:
        f = max(self.floor, self.clock-self.epsilon)
        before = self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        self._fault('before_transaction',failpoint)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('DELETE FROM events WHERE deadline<=?',(f,))
            self._fault('before_floor',failpoint)
            if self.mode != 'no-floor':
                self.db.execute("UPDATE meta SET value=? WHERE key='floor'",(f,))
            self._fault('before_commit',failpoint)
            self.db.commit()
        except BaseException:
            self.db.rollback(); raise
        self._fault('after_commit_before_reply',failpoint)
        after = self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        return {'before':before,'after':after,'floor':self.floor}

    def _get(self, ident: str) -> dict | None:
        row = self.db.execute("SELECT payload FROM events WHERE id=? AND kind='grant'",(ident,)).fetchone()
        return None if row is None else json.loads(row[0])

    def _first_revoked(self, consider: list[dict]) -> str | None:
        """Return the nearest revoked ancestor in the original chain order."""
        if self.mode == 'lease':
            return None
        if self.mode == 'lww':
            # This deliberately unsafe comparator has timestamp semantics,
            # unlike the immutable revocation-membership test.
            for g in consider:
                row = self.db.execute("SELECT id,stamp FROM events WHERE kind='revoke' AND target=? ORDER BY id LIMIT 1",(g['id'],)).fetchone()
                revoked = row is not None or g['id'] in self.volatile
                if row is not None:
                    stamp = self.db.execute('SELECT stamp FROM events WHERE id=?',(g['id'],)).fetchone()[0]
                    revoked = row[1] >= stamp
                if revoked:
                    return g['id']
            return None
        # Check the leaf first: an immediately revoked request needs only the
        # original single indexed query, regardless of ancestry depth.
        leaf = consider[0]['id']
        if leaf in self.volatile or self.db.execute(
                "SELECT 1 FROM events WHERE kind='revoke' AND target=? LIMIT 1",(leaf,)).fetchone() is not None:
            return leaf
        identifiers = [g['id'] for g in consider[1:]]
        if not identifiers:
            return None
        placeholders = ','.join('?' for _ in identifiers)
        revoked = {row[0] for row in self.db.execute(
            "SELECT target FROM events WHERE kind='revoke' AND target IN ("+placeholders+")",
            identifiers)}
        revoked.update(self.volatile)
        return next((ident for ident in identifiers if ident in revoked), None)

    def authorize(self, cap: str, actor: int, right: int, service: str, with_snapshot: bool = False) -> dict:
        if not isinstance(cap,str) or len(cap)!=64 or service not in {'svc0','svc1','svc2','svc3','svc4'} or type(actor) is not int or not 0 <= actor < N or type(right) is not int or right<=0 or right >= 1 << 32:
            raise ValueError('request')
        chain, seen, cur = [], set(), cap
        reason, atom = 'allow', None
        while cur is not None:
            if cur in seen or len(chain) >= MAX_CHAIN:
                reason,atom = 'chain_limit',cur; break
            seen.add(cur)
            g = self._get(cur)
            if g is None:
                reason,atom = 'missing',cur; break
            chain.append(g)
            cur = g['parent']
        if reason == 'allow':
            leaf = chain[0]
            if leaf['service'] != service or chain[-1]['service'] != 'svc'+str(chain[-1]['issuer']):
                reason,atom='service',leaf['id']
            elif leaf['subject'] != actor:
                reason,atom='subject',leaf['id']
            elif (right & leaf['rights']) != right:
                reason,atom='right',leaf['id']
            else:
                # Validate attenuation BEFORE any revocation or expiry decision.
                for child,parent in zip(chain,chain[1:]):
                    if (child['service'] != parent['service'] or child['issuer'] != parent['subject'] or child['rights'] & ~parent['rights'] or
                        any(c>p for c,p in zip(child['deadlines'],parent['deadlines']))):
                        reason,atom='attenuation',child['id']; break
                if reason == 'allow':
                    consider = chain[:1] if self.mode in {'acl','leaf-only'} else chain
                    revoked = self._first_revoked(consider)
                    if revoked is not None:
                        reason,atom='revoked',revoked
                    if reason=='allow':
                        d=leaf['deadlines'][self.node]
                        upper=self.clock if self.mode=='clock-unsafe' else self.clock+self.epsilon
                        if d<=self.floor or upper>=d:
                            reason,atom='expired',leaf['id']
        out={'allow':reason=='allow','reason':reason,'atom':atom,'chain':[g['id'] for g in chain],
             'node':self.node,'clock':self.clock,'epsilon':self.epsilon,'floor':self.floor,
             'request':{'cap':cap,'actor':actor,'right':right,'service':service}}
        if with_snapshot:
            out['snapshot']=self.events()
        return out

    def delegate(self, parent_id: str, actor: int, subject: int, rights: int, deadlines: list[int], nonce: str) -> dict:
        """Owned-emulator issuance with an explicit acting principal.

        RPC identity is NOT a production authenticated session: ``actor`` is a
        model input supplied by the administrative harness. The state transition
        nevertheless checks that the actor is the parent's subject before using
        that identity as the child's issuer. The serial server runs authorization
        and insertion without an await between them, so no concurrent local request
        can revoke between those transitions.
        """
        parent = self._get(parent_id)
        if parent is None:
            return {'issued': False, 'reason': 'missing'}
        d = self.authorize(parent_id,actor,rights,parent['service'])
        if not d['allow']:
            return {'issued': False, 'reason': d['reason']}
        # A usable parent at the maximum depth cannot issue an unusable child.
        if len(d['chain']) >= MAX_CHAIN:
            return {'issued': False, 'reason': 'chain_limit'}
        child = grant(actor,subject,parent,rights,deadlines,nonce)
        if not shape(child) or any(c>p for c,p in zip(deadlines,parent['deadlines'])):
            return {'issued': False, 'reason': 'attenuation'}
        # Avoid knowingly issuing a token already unusable at this gateway.
        if deadlines[self.node] <= max(self.floor,self.clock+self.epsilon):
            return {'issued': False, 'reason': 'expired'}
        self.ingest([child])
        return {'issued': True, 'reason': 'allow', 'event': child}

    def stats(self) -> dict:
        rows=list(self.db.execute('SELECT kind,COUNT(*),SUM(LENGTH(payload)) FROM events GROUP BY kind'))
        return {'records':sum(r[1] for r in rows),'json_bytes':sum(r[2] for r in rows),
                'grants':sum(r[1] for r in rows if r[0]=='grant'),
                'revocations':sum(r[1] for r in rows if r[0]=='revoke'), 'floor':self.floor,
                'sqlite_bytes':sum(p.stat().st_size for p in self.path.parent.glob(self.path.name+'*'))}

    def close(self):
        self.db.close()
