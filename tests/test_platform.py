import os
import tempfile
import unittest

from aegis import storage


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = storage.DB_PATH
        self.original_data_dir = storage.DATA_DIR
        storage.DATA_DIR = self.temp_dir.name
        storage.DB_PATH = os.path.join(self.temp_dir.name, "test.db")

    def tearDown(self) -> None:
        storage.DB_PATH = self.original_db_path
        storage.DATA_DIR = self.original_data_dir
        self.temp_dir.cleanup()

    def test_classifies_dangerous_commands(self) -> None:
        self.assertEqual(storage.classify_event("ssh_command", command="cat /etc/passwd"), "CRITICAL")
        self.assertEqual(storage.classify_event("ssh_command", command="whoami"), "MEDIUM")
        self.assertEqual(storage.classify_event("web_request", path="/", method="GET"), "LOW")
        self.assertEqual(storage.classify_event("web_request", path="/admin", method="GET"), "HIGH")

    def test_event_round_trip(self) -> None:
        storage.record_event("web_request", "127.0.0.1", method="POST", path="/login", details="username=test")
        events = storage.fetch_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "web_request")
        self.assertEqual(events[0]["severity"], "MEDIUM")
        self.assertEqual(events[0]["path"], "/login")


if __name__ == "__main__":
    unittest.main()
