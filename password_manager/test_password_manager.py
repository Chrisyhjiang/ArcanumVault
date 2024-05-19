import os
import unittest
from click.testing import CliRunner
from cli import vault

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        """Set up the test environment"""
        self.runner = CliRunner()
        # Ensure the data directory and key file are fresh for each test
        if os.path.exists('.password_manager'):
            for root, dirs, files in os.walk('.password_manager', topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir('.password_manager')
        os.makedirs('.password_manager/data')
        with open('.password_manager/key.key', 'wb') as f:
            f.write(Fernet.generate_key())

    def test_authenticate(self):
        """Test the authenticate command"""
        result = self.runner.invoke(vault, ['authenticate'], input='password\npassword\n')
        self.assertIn('Authentication succeeded.', result.output)

    def test_insert(self):
        """Test the insert command"""
        self.runner.invoke(vault, ['authenticate'], input='password\npassword\n')
        result = self.runner.invoke(vault, ['insert'], input='example.com\nExample description\nuser@example.com\npassword\npassword\n')
        self.assertIn('Password for example.com inserted', result.output)

    def test_show(self):
        """Test the show command"""
        self.runner.invoke(vault, ['authenticate'], input='password\npassword\n')
        self.runner.invoke(vault, ['insert'], input='example.com\nExample description\nuser@example.com\npassword\npassword\n')
        result = self.runner.invoke(vault, ['show', 'example.com'])
        self.assertIn('Password for example.com:', result.output)

    def test_remove(self):
        """Test the remove command"""
        self.runner.invoke(vault, ['authenticate'], input='password\npassword\n')
        self.runner.invoke(vault, ['insert'], input='example.com\nExample description\nuser@example.com\npassword\npassword\n')
        result = self.runner.invoke(vault, ['remove', 'example.com'])
        self.assertIn('Password with vault ID', result.output)

    def test_generate(self):
        """Test the generate command"""
        self.runner.invoke(vault, ['authenticate'], input='password\npassword\n')
        result = self.runner.invoke(vault, ['generate', 'example.com', '16'], input='Example description\nuser@example.com\n')
        self.assertIn('Generated password for example.com', result.output)

    def test_reformat(self):
        """Test the reformat command"""
        self.runner.invoke(vault, ['authenticate'], input='password\npassword\n')
        self.runner.invoke(vault, ['insert'], input='example.com\nExample description\nuser@example.com\npassword\npassword\n')
        result = self.runner.invoke(vault, ['reformat'])
        self.assertIn('Reformatted example.com with vault ID', result.output)

    def test_update(self):
        """Test the update command"""
        self.runner.invoke(vault, ['authenticate'], input='password\npassword\n')
        self.runner.invoke(vault, ['insert'], input='example.com\nExample description\nuser@example.com\npassword\npassword\n')
        result = self.runner.invoke(vault, ['update', 'example.com'], input='New description\nnewuser@example.com\nnewpassword\nnewpassword\n')
        self.assertIn('Updated entry with vault ID', result.output)

    def test_rotate_key(self):
        """Test the rotate-key command"""
        self.runner.invoke(vault, ['authenticate'], input='password\npassword\n')
        self.runner.invoke(vault, ['insert'], input='example.com\nExample description\nuser@example.com\npassword\npassword\n')
        result = self.runner.invoke(vault, ['rotate-key'])
        self.assertIn('Key rotation completed successfully.', result.output)

    def test_delete_all(self):
        """Test the delete-all command"""
        self.runner.invoke(vault, ['authenticate'], input='password\npassword\n')
        self.runner.invoke(vault, ['insert'], input='example.com\nExample description\nuser@example.com\npassword\npassword\n')
        result = self.runner.invoke(vault, ['delete-all'])
        self.assertIn('All password entries have been deleted.', result.output)

if __name__ == '__main__':
    unittest.main()
