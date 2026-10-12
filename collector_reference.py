"""Straightforward durable latest-state + confirmation/lease-expiry reference.

Same target binding, validation, information, SQLite FULL/WAL durability, and
transaction/reply boundary as ClosureJournal. Save the latest sufficient state
on every observation, then query it for the reply. This is a local reference,
not a port of Chubby or Maat. Shared validation deliberately isolates SQL work;
it does not make this an independent input-validation or safety oracle.
"""
from collector import ClosureJournal, advance_lower_bound


class DurableReference(ClosureJournal):
    def observe(self, clock, receipts, failpoint=None):
        incoming = self._validate_observation(clock, receipts, failpoint)
        self._fault(failpoint, 'before_transaction')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            lower, mask = self.db.execute(
                'SELECT lower_time,receipt_mask FROM certificate WHERE singleton=1'
            ).fetchone()
            lower = advance_lower_bound(lower, clock, self.epsilon)
            mask |= incoming
            self.db.execute(
                'UPDATE certificate SET lower_time=?,receipt_mask=? WHERE singleton=1',
                (lower, mask),
            )
            self._fault(failpoint, 'before_commit')
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        self._fault(failpoint, 'after_commit_before_reply')
        return self.status()
