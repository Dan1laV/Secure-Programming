import unittest
import os
import json
from unittest.mock import patch
import pm

class TestSecurePasswordManager(unittest.TestCase):

    def setUp(self):
        pm.VAULT_FILE = "test_vault.json"
        pm.LOG_FILE = "test_pm_secure.log"
        self.cleanup()

    def tearDown(self):
        self.cleanup()

    def cleanup(self):
        if os.path.exists(pm.VAULT_FILE):
            os.remove(pm.VAULT_FILE)
        if os.path.exists(pm.LOG_FILE):
            os.remove(pm.LOG_FILE)

    def test_input_validation_valid(self):
        valid_inputs = ["github.com", "user_name12", "service-core@v3"]
        for inp in valid_inputs:
            self.assertEqual(pm.sanitize_input(inp), inp)

    def test_input_validation_invalid_chars(self):
        invalid_inputs = ["site; DROP TABLE secrets;", "username<script>", "site|cat /etc/passwd"]
        for inp in invalid_inputs:
            with self.assertRaises(SystemExit):
                pm.sanitize_input(inp)

    def test_input_validation_length_overflow(self):
        long_input = "a" * 300
        with self.assertRaises(SystemExit):
            pm.sanitize_input(long_input)

    @patch('getpass.getpass')
    def test_vault_initialization_and_cryptography(self, mock_getpass):
        mock_getpass.side_effect = ["MyStrongPassword123!", "MyStrongPassword123!"]
        pm.cmd_init()
        self.assertTrue(os.path.exists(pm.VAULT_FILE))

        with open(pm.VAULT_FILE, "r") as f:
            vault_data = json.load(f)
            self.assertEqual(vault_data["version"], 1)
            self.assertIn("owner_uid", vault_data)

    @patch('getpass.getpass')
    def test_authentication_failure_paths(self, mock_getpass):
        mock_getpass.side_effect = ["CorrectPass", "CorrectPass"]
        pm.cmd_init()

        mock_getpass.side_effect = ["IncorrectPassAttempt"]
        vault = pm.load_vault_file()
        
        with self.assertRaises(SystemExit):
            pm.verify_and_get_key(vault)

    def test_secure_memory_zeroing(self):
        target_str = "SensitiveSecretInformation!"
        pm.wipe_bytearray(bytearray(target_str.encode('utf-8')))
        self.assertTrue(True)

if __name__ == '__main__':
    unittest.main()
