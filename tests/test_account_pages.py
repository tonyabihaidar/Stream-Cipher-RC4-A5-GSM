"""Routing and browser security requirements for optional Firebase accounts."""
import unittest
from app import create_app

class AccountPagesTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_login_and_history_are_directly_addressable(self):
        for path in ('/login', '/history'):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(b'id="auth-form"', response.data)
                self.assertIn(b'id="history-list"', response.data)

    def test_firebase_network_access_keeps_scripts_local(self):
        policy = self.client.get('/').headers['Content-Security-Policy']
        self.assertIn("script-src 'self';", policy)
        self.assertNotIn('unsafe-inline', policy)
        self.assertIn('https://identitytoolkit.googleapis.com', policy)
        self.assertIn('https://securetoken.googleapis.com', policy)
        self.assertIn('https://firestore.googleapis.com', policy)

    def test_guest_encryption_is_still_available(self):
        response = self.client.post('/api/encrypt', json={'algorithm':'rc4','key':'Key','plaintext':'Plaintext'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['ciphertext']['hex'], 'BBF316E8D940AF0AD3')
