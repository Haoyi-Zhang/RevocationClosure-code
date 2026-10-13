"""Environment records must describe the assigned runner, not a stored host."""
import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import run


class EnvironmentTests(unittest.TestCase):
    def test_windows_queries_current_processor(self):
        record = {'Name': 'test processor', 'NumberOfCores': 4, 'NumberOfLogicalProcessors': 8}
        with patch.object(run.sys, 'platform', 'win32'), \
             patch.object(run.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps(record))) as query:
            result = run.host_observation()
        self.assertEqual(result['processor_query'], record)
        self.assertEqual(query.call_args.kwargs['timeout'], 30)

    def test_unavailable_windows_query_is_unknown(self):
        with patch.object(run.sys, 'platform', 'win32'), \
             patch.object(run.subprocess, 'run', side_effect=OSError('unavailable')):
            result = run.host_observation()
        self.assertIsNone(result['processor_query'])
        self.assertEqual(result['query_error'], 'OSError')

    def test_invalid_windows_record_is_not_filled(self):
        with patch.object(run.sys, 'platform', 'win32'), \
             patch.object(run.subprocess, 'run', return_value=SimpleNamespace(stdout='not JSON')):
            result = run.host_observation()
        self.assertIsNone(result['processor_query'])
        self.assertEqual(result['query_error'], 'JSONDecodeError')

    def test_linux_uses_local_cpuinfo(self):
        with patch.object(run.sys, 'platform', 'linux'), \
             patch.object(run.Path, 'read_text', return_value='processor : 0\nmodel name : test Linux CPU\n'):
            result = run.host_observation()
        self.assertEqual(result['processor_model'], 'test Linux CPU')
        self.assertNotIn('processor_query', result)


if __name__ == '__main__':
    unittest.main()
