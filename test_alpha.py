# File: test_alpha.py
import unittest
import os
import main

class TestAlpha(unittest.TestCase):
    def setUp(self):
        main.AGENTS_FILE = "test_agents.json"
        main.CALLS_FILE = "test_calls.json"
        main.save_data(main.AGENTS_FILE, [{"id": "AG001", "name": "Test", "status": "Available"}])

    def tearDown(self):
        if os.path.exists(main.AGENTS_FILE): os.remove(main.AGENTS_FILE)
        if os.path.exists(main.CALLS_FILE): os.remove(main.CALLS_FILE)

    def test_call_success(self):
        self.assertTrue(main.record_call("Inbound", "AG001", "John", "123"))

    def test_busy_agent(self):
        main.update_agent_status("AG001", "Busy")
        self.assertFalse(main.record_call("Inbound", "AG001", "John", "123"))

if __name__ == '__main__':
    unittest.main()