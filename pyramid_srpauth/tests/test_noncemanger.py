import unittest
import time

from pyramid.testing import DummyRequest

from pyramid_srpauth.noncemanager import SignedNonceManager


def make_request(**kwds):
    environ = {}
    environ["wsgi.version"] = (1, 0)
    environ["wsgi.url_scheme"] = "http"
    environ["SERVER_NAME"] = "localhost"
    environ["SERVER_PORT"] = "80"
    environ["REQUEST_METHOD"] = "GET"
    environ["SCRIPT_NAME"] = ""
    environ["PATH_INFO"] = "/"
    environ.update(kwds)
    return DummyRequest(environ=environ)


class TestSignedNonceManager(unittest.TestCase):
    """Testcases for the SignedNonceManager class."""

    def test_nonce_validation(self):
        nm = SignedNonceManager(timeout=0.1)
        request = make_request(HTTP_USER_AGENT="good-user")
        # malformed nonces should be invalid
        self.failIf(nm.is_valid_nonce("", request))
        self.failIf(nm.is_valid_nonce("IHACKYOU", request))
        # immediately-generated nonces should be valid.
        nonce = nm.generate_nonce(request)
        self.failUnless(nm.is_valid_nonce(nonce, request))
        # tampered-with nonces should be invalid
        self.failIf(nm.is_valid_nonce(nonce + "IHACKYOU", request))
        # nonces are only valid for specific user-agent
        request2 = make_request(HTTP_USER_AGENT="nasty-hacker")
        self.failIf(nm.is_valid_nonce(nonce, request2))
        # expired nonces should be invalid
        self.failUnless(nm.is_valid_nonce(nonce, request))
        time.sleep(0.1)
        self.failIf(nm.is_valid_nonce(nonce, request))

    def test_next_nonce_generation(self):
        nm = SignedNonceManager(soft_timeout=0.1)
        request = make_request()
        nonce1 = nm.generate_nonce(request)
        self.failUnless(nm.is_valid_nonce(nonce1, request))

        # next-nonce is not generated until the soft timeout expires.
        self.assertEquals(nm.get_next_nonce(nonce1, request), None)
        time.sleep(0.1)
        nonce2 = nm.get_next_nonce(nonce1, request)
        self.assertNotEquals(nonce2, None)
        self.assertNotEquals(nonce2, nonce1)
        self.failUnless(nm.is_valid_nonce(nonce1, request))
        self.failUnless(nm.is_valid_nonce(nonce2, request))

    def test_nonce_count_management(self):
        nm = SignedNonceManager(timeout=0.1)
        request = make_request()
        nonce1 = nm.generate_nonce(request)
        self.assertEquals(nm.get_nonce_count(nonce1), None)
        nm.set_nonce_count(nonce1, 1)
        self.assertEquals(nm.get_nonce_count(nonce1), 1)
        # purging won't remove it until it has expired.
        nm._purge_expired_nonces()
        self.assertEquals(nm.get_nonce_count(nonce1), 1)
        time.sleep(0.1)
        nm._purge_expired_nonces()
        self.assertEquals(nm.get_nonce_count(nonce1), None)

    def test_auto_purging_of_expired_nonces(self):
        nm = SignedNonceManager(timeout=0.2)
        request = make_request()
        nonce1 = nm.generate_nonce(request)
        nm.set_nonce_count(nonce1, 1)
        time.sleep(0.1)
        # nonce1 hasn't expired, so adding a new one won't purge it
        nonce2 = nm.generate_nonce(request)
        nm.set_nonce_count(nonce2, 1)
        self.assertEquals(nm.get_nonce_count(nonce1), 1)
        time.sleep(0.1)
        # nonce1 has expired, it should be purged when adding another.
        # nonce2 hasn't expired so it should remain in memory.
        nonce3 = nm.generate_nonce(request)
        nm.set_nonce_count(nonce3, 1)
        self.assertEquals(nm.get_nonce_count(nonce1), None)
        self.assertEquals(nm.get_nonce_count(nonce2), 1)

    def test_pseudorandom_bytes(self):
        nm = SignedNonceManager()
        request = make_request()
        nonce1 = nm.generate_nonce(request)
        nonce2 = nm.generate_nonce(request)
        for size in (4, 8, 32, 64, 212, 1234):
            # We should be able to generate strings of any size.
            self.assertEquals(len(nm.get_prandom_bytes(nonce1, size)), size)
            # We should get the same bytes from the same nonce.
            self.assertEquals(nm.get_prandom_bytes(nonce1, size),
                              nm.get_prandom_bytes(nonce1, size))
            self.assertEquals(nm.get_prandom_bytes(nonce2, size),
                              nm.get_prandom_bytes(nonce2, size))
            # We should get different bytes from different nonces.
            self.assertNotEquals(nm.get_prandom_bytes(nonce1, size),
                                 nm.get_prandom_bytes(nonce2, size))
