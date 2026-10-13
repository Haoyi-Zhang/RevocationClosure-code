"""Transaction ordering checks on disposable local SQLite databases."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capability import Store, grant


class BeforeBegin:
    """Schedule a second connection immediately before the first gets its lock."""
    def __init__(self, connection, action):
        self.connection = connection
        self.action = action
        self.fired = False

    def execute(self, sql, *args):
        if sql == 'BEGIN IMMEDIATE' and not self.fired:
            self.fired = True
            self.action()
        return self.connection.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self.connection, name)


class StopAtBoundary(RuntimeError):
    pass


class CompactionTransactions(unittest.TestCase):
    def make_store(self, path, epsilon=0):
        store = Store(path, 0, epsilon)
        self.addCleanup(store.db.close)
        return store

    def test_floor_join_reads_the_locked_state(self):
        # Both readings can occur at the same true time under the shared bound.
        for epsilon in (1, 2, 6, 15):
            for older_clock in (40, 100, 300):
                with self.subTest(epsilon=epsilon, clock=older_clock):
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / 'gateway.sqlite'
                        older = Store(path, 0, epsilon)
                        newer = Store(path, 0, epsilon)
                        try:
                            older.set_clock(older_clock)
                            newer.set_clock(older_clock + epsilon)
                            older.db = BeforeBegin(older.db, newer.compact)
                            result = older.compact()
                            self.assertTrue(older.db.fired)
                            self.assertEqual(result['floor'], older_clock)
                            self.assertEqual(newer.floor, older_clock)
                        finally:
                            older.db.close()
                            newer.db.close()

    def test_counts_and_floor_describe_one_committed_compaction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gateway.sqlite'
            older = Store(path, 0, 10)
            newer = Store(path, 0, 10)
            try:
                older.ingest([grant(0, 1, None, 7, [deadline] * 5,
                                    'transaction-%d' % deadline)
                              for deadline in (30, 95, 150)])
                older.set_clock(100)
                newer.set_clock(110)
                older.db = BeforeBegin(older.db, newer.compact)
                self.assertEqual(older.compact(), {'before': 1, 'after': 1, 'floor': 100})
                self.assertEqual(newer.floor, 100)
            finally:
                older.db.close()
                newer.db.close()

    def test_precommit_interruption_rolls_back_rows_and_floor(self):
        for boundary in ('before_floor', 'before_commit'):
            with self.subTest(boundary=boundary):
                with tempfile.TemporaryDirectory() as directory:
                    store = Store(Path(directory) / 'gateway.sqlite', 0)
                    try:
                        event = grant(0, 1, None, 7, [30] * 5, 'rollback')
                        store.ingest([event])
                        store.set_clock(50)
                        def stop(point, selected):
                            if point == selected:
                                raise StopAtBoundary(point)
                        store._fault = stop
                        with self.assertRaises(StopAtBoundary):
                            store.compact(boundary)
                        self.assertEqual(store.floor, 0)
                        self.assertEqual(store.events(), [event])
                    finally:
                        store.db.close()

    def test_postcommit_reply_interruption_survives_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gateway.sqlite'
            store = Store(path, 0)
            try:
                store.ingest([grant(0, 1, None, 7, [30] * 5, 'reply')])
                store.set_clock(50)
                def stop(point, selected):
                    if point == selected:
                        raise StopAtBoundary(point)
                store._fault = stop
                with self.assertRaises(StopAtBoundary):
                    store.compact('after_commit_before_reply')
            finally:
                store.db.close()
            recovered = Store(path, 0)
            try:
                self.assertEqual(recovered.floor, 50)
                self.assertEqual(recovered.events(), [])
                self.assertEqual(recovered.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            finally:
                recovered.db.close()

    def test_serial_compaction_keeps_the_previous_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'gateway.sqlite', 0, 5)
            try:
                store.set_clock(100)
                self.assertEqual(store.compact()['floor'], 95)
                store.set_clock(97)
                self.assertEqual(store.compact()['floor'], 95)
            finally:
                store.db.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
