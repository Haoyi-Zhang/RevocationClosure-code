"""Deterministic finite capability fixtures with public experiment keys."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
N = 5
MAX_TIME = 1 << 53
MAX_CHAIN = 256
PRINCIPAL_KEYS = tuple(f"public-toy-key-{i}-not-a-credential".encode() for i in range(N))
RECEIPT_KEYS = tuple(f"public-toy-gateway-receipt-key-{i}-not-a-credential".encode() for i in range(N))


def owned(path: Path) -> Path:
    path = Path(path).resolve()
    if not path.is_relative_to(HERE) or path == HERE:
        raise ValueError("outside capacity module")
    return path


def packed(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def integer(value, maximum=MAX_TIME) -> bool:
    return type(value) is int and 0 <= value <= maximum


def hexid(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def signed(body: dict, key: bytes) -> dict:
    result = dict(body, id=hashlib.sha256(packed(body)).hexdigest())
    result["mac"] = hmac.new(key, packed(result), hashlib.sha256).hexdigest()
    return result


def authenticated(record, field, keys) -> bool:
    if not isinstance(record, dict) or not integer(record.get(field), N - 1):
        return False
    try:
        body = {k: v for k, v in record.items() if k not in {"id", "mac"}}
        expected = signed(body, keys[record[field]])
        return record["id"] == expected["id"] and hmac.compare_digest(record["mac"], expected["mac"])
    except (KeyError, TypeError, ValueError):
        return False


def valid_event(event) -> bool:
    if not authenticated(event, "issuer", PRINCIPAL_KEYS):
        return False
    if event.get("kind") == "grant":
        return (set(event) == {"kind", "issuer", "subject", "parent", "rights", "deadlines", "nonce", "service", "id", "mac"}
                and integer(event["subject"], N - 1)
                and (event["parent"] is None or hexid(event["parent"]))
                and integer(event["rights"], (1 << 32) - 1) and event["rights"] > 0
                and isinstance(event["service"], str) and event["service"] in {f"svc{i}" for i in range(N)}
                and isinstance(event["deadlines"], list) and len(event["deadlines"]) == N
                and all(integer(d) for d in event["deadlines"])
                and isinstance(event["nonce"], str) and 0 < len(event["nonce"]) <= 128
                and len(packed(event)) <= 512)
    if event.get("kind") == "revoke":
        target = event.get("target")
        return (set(event) == {"kind", "issuer", "target", "id", "mac"}
                and isinstance(target, dict) and target.get("kind") == "grant"
                and valid_event(target) and event["issuer"] == target["issuer"]
                and len(packed(event)) <= 768)
    return False


def grant(issuer, subject, parent, rights, deadlines, nonce):
    return signed(dict(kind="grant", issuer=issuer, subject=subject,
                       parent=None if parent is None else parent["id"], rights=rights,
                       deadlines=list(deadlines), nonce=nonce,
                       service=f"svc{issuer}" if parent is None else parent["service"]), PRINCIPAL_KEYS[issuer])


def revoke(target):
    return signed(dict(kind="revoke", issuer=target["issuer"], target=target), PRINCIPAL_KEYS[target["issuer"]])


def receipt(node, event):
    return signed(dict(kind="receipt", gateway=node, revocation=event["id"], target=event["target"]["id"]), RECEIPT_KEYS[node])


def valid_receipt(value, node, event):
    return (authenticated(value, "gateway", RECEIPT_KEYS)
            and set(value) == {"kind", "gateway", "revocation", "target", "id", "mac"}
            and value["kind"] == "receipt" and value["gateway"] == node
            and value["revocation"] == event["id"] and value["target"] == event["target"]["id"])


def target(event):
    return event if event["kind"] == "grant" else event["target"]


def horizon(event):
    return max(target(event)["deadlines"])
