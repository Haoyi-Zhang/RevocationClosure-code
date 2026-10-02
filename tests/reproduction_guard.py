"""Check that resumable reproduction cannot mix changed source generations."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reproduce import prepare_source_snapshot, source_files


def run(out: Path) -> dict:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        candidate = temporary / 'candidate'
        reproduction = temporary / 'reproduction'
        for relative in source_files(root):
            destination = candidate / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / relative, destination)

        snapshot, count = prepare_source_snapshot(candidate, reproduction, False)
        assert snapshot.is_dir()
        _, resumed_count = prepare_source_snapshot(candidate, reproduction, True)
        assert resumed_count == count
        assert all((candidate / rel).read_bytes() == (snapshot / rel).read_bytes()
                   for rel in source_files(candidate))

        changed = candidate / 'capability.py'
        original = changed.read_bytes()
        changed.write_bytes(original + b'\n# deliberate guard mutation\n')
        try:
            prepare_source_snapshot(candidate, reproduction, True)
        except ValueError as error:
            changed_rejected = 'source changed' in str(error)
        else:
            changed_rejected = False
        assert changed_rejected

        changed.write_bytes(original)
        removed = candidate / 'tests' / 'clock_bounds.py'
        removed.unlink()
        try:
            prepare_source_snapshot(candidate, reproduction, True)
        except ValueError as error:
            set_change_rejected = 'file set changed' in str(error)
        else:
            set_change_rejected = False
        assert set_change_rejected

    result = {
        'retained_source_files': count,
        'unchanged_resume_accepted': True,
        'changed_source_resume_rejected': changed_rejected,
        'changed_source_set_resume_rejected': set_change_rejected,
        'fresh_output_required_after_source_change': True,
        'scope': (
            'Finite self-test of the reproduction guard; it checks byte closure of the '
            'retained Python source set, not scientific correctness.'
        ),
    }
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'reproduction-guard.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=Path('results'))
    args = parser.parse_args()
    print(json.dumps(run(args.out), indent=2))
