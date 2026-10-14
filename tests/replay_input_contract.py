"""Owned replay admission controls, with no service or upstream execution."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from capability import grant
from verifier import Replay, evaluate

class ReplayInputContractTests(unittest.TestCase):
    def setUp(self):
        self.event=grant(0,1,None,1,[100]*5,'owned-replay-contract')
        self.request={'cap':self.event['id'],'actor':1,'right':1,'service':'svc0'}

    def test_one_shot_and_nonlist_batches_reject_without_state_change(self):
        replay=Replay(0)
        for batch in (iter([self.event]),(),{},'',None):
            with self.subTest(container=type(batch).__name__):
                with self.assertRaisesRegex(ValueError,'replay record'):replay.ingest(batch)
                self.assertEqual(replay.records,{})

    def test_valid_batch_and_invalid_later_item_preserve_atomic_admission(self):
        replay=Replay(0);replay.ingest([self.event])
        self.assertEqual(set(replay.records),{self.event['id']})
        with self.assertRaisesRegex(ValueError,'replay record'):replay.ingest([self.event,{'kind':'grant'}])
        self.assertEqual(set(replay.records),{self.event['id']})
        self.assertEqual(replay.decide(self.request,0),('allow',None))

    def test_snapshot_input_has_the_same_list_contract(self):
        self.assertEqual(evaluate([self.event],self.request,0,0,0,0),('allow',None))
        for batch in (iter([self.event]),(),{},'',None):
            with self.subTest(container=type(batch).__name__):
                with self.assertRaisesRegex(ValueError,'snapshot authentication or shape'):
                    evaluate(batch,self.request,0,0,0,0)

if __name__=='__main__':unittest.main()
