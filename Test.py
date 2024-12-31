import unittest
import sqlite3
from main import User, Database, Credential

class TestCyberEsportsApp(unittest.TestCase):

    def setUp(self):
        self.db = Database(':memory:')  # Use in-memory database for testing
        self.user = User(self.db)
        self.credential = Credential(self.db)

    def test_password_strength_strong(self):
        self.assertTrue(self.user.evaluate_password("Password1!@"))

    def test_password_strength_weak(self):
        self.assertFalse(self.user.evaluate_password("Pass1"))

    def test_2fa_generation(self):
        code = self.user.generate_two_factor_code()
        self.assertEqual(len(code), 4)
        self.assertTrue(code.isdigit())

    def test_database_encryption_decryption(self):
        test_data = "testdata"
        encrypted = self.db.encrypt(test_data)
        decrypted = self.db.decrypt(encrypted)
        self.assertEqual(test_data, decrypted)

    def test_sql_injection_protection(self):
        malicious_input = "'; DROP TABLE users; --"
        result = self.db.is_duplicate(malicious_input)
        self.assertFalse(result)  # Should not cause errors or drop table

    def test_file_handling_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            open('nonexistent_file.txt', 'r')

    def test_invalid_username_or_password(self):
        result = self.db.verify_login('wrong_user', 'wrong_password')
        self.assertFalse(result)

    def test_invalid_password_format(self):
        self.assertFalse(self.user.evaluate_password("NoSpecial123"))

    def test_empty_fields(self):
        self.assertFalse(self.user.create_account("", ""))

    def test_large_input(self):
        large_input = "A" * 1000
        self.assertFalse(self.user.create_account(large_input, large_input))

    def test_special_characters(self):
        special_input = "user!@#$%^&*()"
        self.assertFalse(self.user.create_account(special_input, "Password1!@"))

    def test_session_management_logout(self):
        self.user.login_attempts = {"user": (1, 0)}
        self.user.login_attempts.clear()
        self.assertEqual(self.user.login_attempts, {})

    def tearDown(self):
        self.db.close()


if __name__ == '__main__':
    unittest.main()
