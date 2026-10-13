"""Fresh, subtree-confined generated evidence; no network or project imports."""
import json
from pathlib import Path

from fixtures import owned


def fresh(path):
    path = owned(Path(path))
    if path.exists():
        raise ValueError("output path already exists; choose a fresh run")
    path.mkdir(parents=True)
    return path


def save(path, value):
    path = owned(Path(path))
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")


def compact_state(state):
    return dict(floor=state.floor, grants=sorted(state.grants), revokes=sorted(state.revokes), early=sorted(state.early))
