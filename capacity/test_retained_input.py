"""Retained compression changes the container, not any scientific record."""
import gzip
import json
import lzma
from pathlib import Path
import tempfile
import unittest

from fixtures import HERE
from verify_outputs import read, open_retained


class RetainedInputTests(unittest.TestCase):
    def test_plain_gzip_and_xz_json(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            root = Path(directory).resolve()
            self.assertTrue(root.is_relative_to(HERE))
            value = {'records': [0, 1, True], 'scope': 'finite'}
            payload = json.dumps(value).encode()
            for name, packed in [('data.json', payload),
                                 ('data.json.gz', gzip.compress(payload)),
                                 ('data.json.xz', lzma.compress(payload))]:
                path = root / name
                path.write_bytes(packed)
                self.assertEqual(read(path), value)

    def test_xz_retention_fallback_preserves_lines(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            root = Path(directory).resolve()
            self.assertTrue(root.is_relative_to(HERE))
            payload = b'{"row":1}\n{"row":2}\n'
            (root / 'rows.jsonl.xz').write_bytes(lzma.compress(payload))
            with open_retained(root / 'rows.jsonl.gz') as stream:
                self.assertEqual(stream.read().encode(), payload)

    def test_existing_gzip_has_priority(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            root = Path(directory).resolve()
            self.assertTrue(root.is_relative_to(HERE))
            (root / 'data.json.gz').write_bytes(gzip.compress(b'{"source":"gzip"}'))
            (root / 'data.json.xz').write_bytes(lzma.compress(b'{"source":"xz"}'))
            self.assertEqual(read(root / 'data.json.gz'), {'source': 'gzip'})


if __name__ == '__main__':
    unittest.main()
