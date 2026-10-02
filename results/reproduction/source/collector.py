"""Recovery-stable completion evidence for a fixed, honest gateway audience.

This model consumes explicitly supplied bounded clocks and authenticated fixture
receipts. It does not implement clock synchronization or production credentials.
"""
from __future__ import annotations
import json
import os
import sqlite3
from pathlib import Path
from capability import N, MAX_TIME, packed, shape, receipt_authenticated

FIELDS = {'kind','gateway','revocation','target','id','mac'}

def advance_lower_bound(previous: int, clock: int, epsilon: int) -> int:
    if any(type(x) is not int or not 0 <= x <= MAX_TIME for x in (previous,clock,epsilon)):
        raise ValueError('clock domain')
    if previous > clock + epsilon:
        raise ValueError('clock contradicts retained time evidence')
    return max(previous,0,clock-epsilon)

def coverage(deadlines: list[int], mask: int, lower: int, epsilon: int) -> dict:
    if (not isinstance(deadlines,list) or len(deadlines)!=N or type(mask) is not int
        or not 0<=mask<(1<<N) or any(type(x) is not int or not 0<=x<=MAX_TIME
                                    for x in [*deadlines,lower,epsilon])):
        raise ValueError('coverage domain')
    cover=['receipt' if mask&(1<<i) else 'inert' if d<=epsilon
           else 'expiry' if d<=lower else 'open' for i,d in enumerate(deadlines)]
    unresolved=[i for i,c in enumerate(cover) if c=='open']
    witness=None
    if unresolved:
        i=unresolved[0]
        witness={'gateway':i,'possible_actual_time':lower,
                 'possible_gateway_clock':max(0,lower-epsilon),
                 'gateway_upper_bound':max(lower,epsilon),'target_deadline':deadlines[i]}
    return {'closed':not unresolved,'cover':cover,'lower_time':lower,
            'receipt_mask':mask,'uncovered_witness':witness}

class ClosureJournal:
    """One immutable revoke per SQLite file, with atomic evidence joins."""
    def __init__(self,path:Path,revocation:dict,epsilon:int=0):
        if (not shape(revocation) or revocation['kind']!='revoke' or
            type(epsilon) is not int or not 0<=epsilon<=MAX_TIME):
            raise ValueError('collector configuration')
        self.revocation=json.loads(packed(revocation));self.epsilon=epsilon
        self.db=sqlite3.connect(str(path))
        try:
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('CREATE TABLE IF NOT EXISTS certificate (singleton INTEGER PRIMARY KEY CHECK(singleton=1),config TEXT NOT NULL,lower_time INTEGER NOT NULL,receipt_mask INTEGER NOT NULL)')
            config=packed({'revocation':self.revocation,'epsilon':epsilon,'gateways':N}).decode()
            self.db.execute('INSERT OR IGNORE INTO certificate VALUES (1,?,0,0)',(config,))
            if self.db.execute('SELECT config FROM certificate WHERE singleton=1').fetchone()[0]!=config:
                self.db.rollback();raise ValueError('collector configuration mismatch')
            self.db.commit()
        except BaseException:
            self.db.close();raise
    @staticmethod
    def _fault(selected,current):
        if selected==current:os._exit(70) # only in owned subprocess tests
    def observe(self,clock:int,receipts:list[dict],failpoint:str|None=None)->dict:
        advance_lower_bound(0,clock,self.epsilon)
        if not isinstance(receipts,list) or len(receipts)>2*N:raise ValueError('receipt batch limit')
        incoming=0
        for r in receipts:
            if (not receipt_authenticated(r) or set(r)!=FIELDS or r['kind']!='receipt'
                or r['revocation']!=self.revocation['id'] or r['target']!=self.revocation['target']['id']):
                raise ValueError('invalid or wrong-target receipt')
            incoming|=1<<r['gateway']
        if failpoint not in {None,'before_transaction','before_commit','after_commit_before_reply'}:
            raise ValueError('unknown collector failpoint')
        self._fault(failpoint,'before_transaction')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            lower,mask=self.db.execute('SELECT lower_time,receipt_mask FROM certificate WHERE singleton=1').fetchone()
            lower=advance_lower_bound(lower,clock,self.epsilon);mask|=incoming
            self.db.execute('UPDATE certificate SET lower_time=?,receipt_mask=? WHERE singleton=1',(lower,mask))
            self._fault(failpoint,'before_commit');self.db.commit()
        except BaseException:
            self.db.rollback();raise
        self._fault(failpoint,'after_commit_before_reply')
        return self.status()
    def status(self)->dict:
        lower,mask=self.db.execute('SELECT lower_time,receipt_mask FROM certificate WHERE singleton=1').fetchone()
        return coverage(self.revocation['target']['deadlines'],mask,lower,self.epsilon)
    def close(self):self.db.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
