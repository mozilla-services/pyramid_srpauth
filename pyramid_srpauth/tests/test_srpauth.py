import unittest

import os
import wsgiref.util
from base64 import b64encode

from pyramid.testing import DummyRequest

from pyramid_srpauth import SRPAuthenticationPolicy
from pyramid_srpauth.parseauthz import parse_authz_header
from pyramid_srpauth.utils import (calculate_verifier,
                                   calculate_client_pubkey,
                                   calculate_server_pubkey,
                                   calculate_shared_secret,
                                   calculate_request_hmac,
                                   validate_parameters,
                                   validate_uri,
                                   int_to_bytes,
                                   int_from_bytes,
                                   ALGORITHMS)


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


def get_response(app, request):
    output = []
    def start_response(status, headers, exc_info=None): # NOQA
        output.append(status + "\r\n")
        for name, value in headers:
            output.append("%s: %s\r\n" % (name, value))
        output.append("\r\n")
    for chunk in app(request.environ, start_response):
        output.append(chunk)
    return "".join(output)


def get_password(username):
    return username


def get_verifier(username):
    algorithm = "SRP-1024-SHA1"
    salt = "SALTIMUS PRIME"
    verifier = calculate_verifier({
        "username": username,
        "algorithm": algorithm,
        "salt": salt,
    }, get_password(username))
    return (algorithm, salt, verifier)


def get_challenge(policy, request, username):
    """Get a new srp-hmac-auth challenge from the policy."""
    set_authz_header(request, dict(username=username))
    for name, value in policy.forget(request):
        if name == "WWW-Authenticate":
            req = make_request(HTTP_AUTHORIZATION=value)
            return parse_authz_header(req)
    raise ValueError("policy didn't issue a challenge")


def build_response(params, request, username, password, **kwds):
    """Build a response to the srp-hmac-auth challenge."""
    params = params.copy()
    params.update(kwds)
    params.setdefault("username", username)
    params.setdefault("uri", wsgiref.util.request_uri(request.environ))
    params.setdefault("cnonce", os.urandom(8).encode("hex"))
    params.setdefault("nc", "0000001")
    if "skey" in params:
        response = calculate_request_hmac(request, params,
                                          privkey=12345, password=password)
        params["response"] = response
    set_authz_header(request, params)
    return params


def set_authz_header(request, params):
    """Set Authorization header to match the given params."""
    authz = ", ".join('%s="%s"' % v for v in params.iteritems())
    request.environ["HTTP_AUTHORIZATION"] = "SRP-HMAC " + authz


class EasyNonceManager(object):
    """NonceManager that thinks everything is valid."""

    def generate_nonce(self, request):
        return "aaa"

    def is_valid_nonce(self, nonce, request):
        return True

    def get_next_nonce(self, nonce, request):
        return nonce + "a"

    def get_prandom_bytes(self, nonce, size):
        return "z" * size

    def get_nonce_count(self, nonce):
        return None

    def set_nonce_count(self, nonce, nc):
        return None


class TestSRPAuthenticationPolicy(unittest.TestCase):
    """Testcases for the main SRPAuthenticationPolicy class."""

    def test_from_settings(self):
        def ref(class_name):
            return __name__ + ":" + class_name
        policy = SRPAuthenticationPolicy.from_settings(
                             realm="test",
                             nonce_manager=ref("EasyNonceManager"),
                             domain="http://example.com",
                             get_verifier=ref("get_verifier"),
                             get_password=ref("get_password"))
        self.assertEquals(policy.realm, "test")
        self.assertEquals(policy.domain, "http://example.com")
        self.failUnless(isinstance(policy.nonce_manager, EasyNonceManager))
        self.failUnless(policy.get_verifier is get_verifier)
        self.failUnless(policy.get_password is get_password)

    # Tests for the low-level credentials extraction

    def test_identify_with_no_authz(self):
        policy = SRPAuthenticationPolicy("test")
        request = make_request()
        self.assertEquals(policy.unauthenticated_userid(request), None)

    def test_identify_with_non_digest_authz(self):
        policy = SRPAuthenticationPolicy("test")
        request = make_request(HTTP_AUTHORIZATION="Basic lalalala")
        self.assertEquals(policy.unauthenticated_userid(request), None)
        request = make_request(HTTP_AUTHORIZATION="BrowserID assertion=1234")
        self.assertEquals(policy.unauthenticated_userid(request), None)

    def test_identify_with_invalid_params(self):
        policy = SRPAuthenticationPolicy("test")
        request = make_request(HTTP_AUTHORIZATION="SRP-HMAC realm=Sync")
        self.assertEquals(policy.unauthenticated_userid(request), None)

    def test_identify_with_mismatched_uri(self):
        policy = SRPAuthenticationPolicy("test", get_password=get_password)
        request = make_request(PATH_INFO="/path_one")
        params = get_challenge(policy, request, "tester")
        build_response(params, request, "tester", "tester")
        self.assertNotEquals(policy.unauthenticated_userid(request), None)
        request["PATH_INFO"] = "/path_two"
        self.assertEquals(policy.unauthenticated_userid(request), None)

    def test_identify_with_bad_noncecount(self):
        policy = SRPAuthenticationPolicy("test",
                                          get_password=lambda u: "testing")
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/one")
        # Do an initial auth to get the nonce.
        params = get_challenge(policy, request, "tester")
        build_response(params, request, "tester", "testing", nc="01")
        self.assertNotEquals(policy.unauthenticated_userid(request), None)
        # Authing without increasing nc will fail.
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="01")
        self.assertEquals(policy.unauthenticated_userid(request), None)
        # Authing with a badly-formed nc will fail
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="02XXX")
        self.assertEquals(policy.unauthenticated_userid(request), None)
        # Authing with a badly-formed nc will fail
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="02XXX")
        self.assertEquals(policy.unauthenticated_userid(request), None)
        # Authing with increasing nc will succeed.
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/two")
        build_response(params, request, "tester", "testing", nc="02")
        self.assertNotEquals(policy.unauthenticated_userid(request), None)

    # Tests for various ways that authentication can go right or wrong

    def test_auth_good(self):
        policy = SRPAuthenticationPolicy("test",
                                         get_password=lambda u: "testing")
        request = make_request()
        params = get_challenge(policy, request, "tester")
        build_response(params, request, "tester", "testing")
        self.assertEquals(policy.authenticated_userid(request), "tester")

    def test_auth_good_post(self):
        policy = SRPAuthenticationPolicy("test",
                                         get_password=lambda u: "testing")
        request = make_request(REQUEST_METHOD="POST", PATH_INFO="/do/stuff")
        params = get_challenge(policy, request, "tester")
        build_response(params, request, "tester", "testing")
        self.assertEquals(policy.authenticated_userid(request), "tester")

    def test_auth_good_get_with_vars(self):
        def get_verifier(username):
            params = {
                "username": username,
                "algorithm": "SRP-1024-SHA1",
                "salt": "SALTIPUS REX",
            }
            verifier = calculate_verifier(params, "testing")
            return (params["algorithm"], params["salt"], verifier)
        policy = SRPAuthenticationPolicy("test", get_verifier=get_verifier)
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/hi?who=me")
        params = get_challenge(policy, request, "tester")
        build_response(params, request, "tester", "testing")
        self.assertEquals(policy.authenticated_userid(request), "tester")

    def test_auth_good_contentmd5(self):
        policy = SRPAuthenticationPolicy("test",
                                         get_password=lambda u: "testing")
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/authint",
                               HTTP_CONTENT_MD5="1B2M2Y8AsgTpgAmY7PhCfg==")
        params = get_challenge(policy, request, "tester")
        params = build_response(params, request, "tester", "testing")
        self.assertEquals(policy.authenticated_userid(request), "tester")

    def test_auth_with_no_identity(self):
        policy = SRPAuthenticationPolicy("test",
                                         get_password=lambda u: "testing")
        request = make_request()
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_auth_with_different_realm(self):
        policy = SRPAuthenticationPolicy("test",
                                         get_password=lambda u: "testing")
        request = make_request()
        params = get_challenge(policy, request, "tester")
        params["realm"] = "other-realm"
        build_response(params, request, "tester", "testing")
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_auth_with_no_password_callbacks(self):
        policy = SRPAuthenticationPolicy("test")
        request = make_request()
        params = get_challenge(policy, request, "tester")
        build_response(params, request, "tester", "testing")
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_auth_with_bad_hmac_response(self):
        policy = SRPAuthenticationPolicy("test",
                                         get_password=lambda u: "testing")
        request = make_request()
        params = get_challenge(policy, request, "tester")
        params = build_response(params, request, "tester", "testing")
        params["response"] = "WRONG"
        set_authz_header(request, params)
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_auth_with_failed_password_lookup(self):
        policy = SRPAuthenticationPolicy("test", get_password=lambda u: None)
        request = make_request()
        params = get_challenge(policy, request, "tester")
        build_response(params, request, "tester", "testing")
        self.assertEquals(policy.authenticated_userid(request), None)

    def test_auth_with_missing_nonce(self):
        policy = SRPAuthenticationPolicy("test",
                                         get_password=lambda u: "testing")
        request = make_request()
        params = get_challenge(policy, request, "tester")
        build_response(params, request, "tester", "testing")
        del params["nonce"]
        set_authz_header(request, params)
        self.assertEquals(policy.unauthenticated_userid(request), None)
        self.assertRaises(KeyError, policy._authenticate, params, request)

    def test_auth_with_invalid_contentmd5(self):
        policy = SRPAuthenticationPolicy("test",
                                         get_password=lambda u: "testing")
        request = make_request(REQUEST_METHOD="GET", PATH_INFO="/authint",
                               HTTP_CONTENT_MD5="1B2M2Y8AsgTpgAmY7PhCfg==")
        params = get_challenge(policy, request, "tester")
        build_response(params, request, "tester", "testing")
        request["HTTP_CONTENT_MD5"] = "8baNZjN6gc+g0gdhccuiqA=="
        self.assertEquals(policy.authenticated_userid(request), None)

    # Tests for various cases in the remember() method.

    def test_remember_with_no_authorization(self):
        policy = SRPAuthenticationPolicy("test")
        request = make_request()
        self.assertEquals(policy.remember(request, "user"), None)

    def test_remember_with_no_next_nonce(self):
        policy = SRPAuthenticationPolicy("test")
        request = make_request()
        params = get_challenge(policy, request, "tester")
        params = build_response(params, request, "tester", "testing")
        self.assertEquals(policy.remember(request, "tester"), None)

    def test_remember_with_next_nonce(self):
        policy = SRPAuthenticationPolicy("test",
                                         get_password=get_password,
                                         nonce_manager=EasyNonceManager())
        request = make_request()
        params = get_challenge(policy, request, "tester")
        params = build_response(params, request, "tester", "tester")
        headers = policy.remember(request, "tester")
        self.assertEquals(headers[0][0], "Authentication-Info")

    # Tests for various cases in the challenge() method.

    def test_challenge(self):
        policy = SRPAuthenticationPolicy("test")
        request = make_request()
        response = policy.challenge_view(request)
        response = get_response(response, request)
        self.failUnless(response.startswith("401 Unauthorized"))
        self.failUnless("WWW-Authenticate: SRP-HMAC" in response)

    def test_challenge_with_stale_nonce(self):
        policy = SRPAuthenticationPolicy("test", get_password=get_password)
        request = make_request()
        # Identify with a bad nonce to mark it as stale.
        params = get_challenge(policy, request, "tester")
        params["nonce"] += "STALE"
        params = build_response(params, request, "tester", "testing")
        self.assertEquals(policy.unauthenticated_userid(request), None)
        # The challenge should then include stale=TRUE
        app = policy.challenge_view(request)
        self.assertNotEqual(app, None)
        response = get_response(app, request)
        self.failUnless(response.startswith("401 Unauthorized"))
        self.failUnless('stale="TRUE"' in response)

    def test_challenge_with_extra_domains(self):
        policy = SRPAuthenticationPolicy("test", domain="http://example.com")
        request = make_request()
        app = policy.challenge_view(request)
        self.assertNotEqual(app, None)
        response = get_response(app, request)
        self.failUnless(response.startswith("401 Unauthorized"))
        self.failUnless("http://example.com" in response)


class TestSRPAuthHelpers(unittest.TestCase):
    """Testcases for the various srp-hmac-auth helper functions."""

    def test_validate_parameters(self):
        params = dict(scheme="SRP-HMAC", realm="testrealm", username="tester",
                      nonce="abcdef", response="123456", uri="/my/page",
                      cnonce="98765", ckey="abcdef", algorithm="SRP-1024-SHA1")
        # Missing "nc"
        self.failIf(validate_parameters(params))
        params["nc"] = "0001"
        self.failUnless(validate_parameters(params))
        # Wrong realm
        self.failIf(validate_parameters(params, realm="otherrealm"))
        self.failUnless(validate_parameters(params, realm="testrealm"))
        # Unknown algorithm
        params["algorithm"] = "SRP-UNDEFINED"
        self.failIf(validate_parameters(params))
        params["algorithm"] = "SRP-1024-SHA1"
        self.failUnless(validate_parameters(params))

    def test_validate_uri(self):
        request = make_request(SCRIPT_NAME="/my", PATH_INFO="/page")
        params = dict(scheme="SRP-HMAC", realm="testrealm", username="tester",
                      nonce="abcdef", response="123456", ckey="abcdef",
                      uri="/my/page", cnonce="98765", nc="0001",
                      algorithm="SRP-1024-SHA1")
        # They should be valid as-is.
        self.failUnless(validate_uri(request, params))
        # Using full URI still works
        params["uri"] = "http://localhost/my/page"
        self.failUnless(validate_uri(request, params))
        # Check that query-string is taken into account.
        params["uri"] = "http://localhost/my/page?test=one"
        self.failIf(validate_uri(request, params))
        request.environ["QUERY_STRING"] = "test=two"
        self.failIf(validate_uri(request, params))
        request.environ["QUERY_STRING"] = "test=one"
        self.failUnless(validate_uri(request, params))
        params["uri"] = "/my/page?test=one"
        self.failUnless(validate_uri(request, params))

    def test_int_to_bytes(self):
        for i in xrange(20):
            n = int(os.urandom(10).encode("hex"), 16)
            self.assertEquals(int_from_bytes(int_to_bytes(n)), n)

    def test_rfc5054_example(self):
        # Input parameters as defined in the RFC.
        username = "alice"
        password = "password123"
        algorithm = "SRP-1024-SHA1"
        salt = "BEB25379 D1A8581E B5A72767 3A2441EE"
        salt = salt.replace(" ", "").decode("hex")
        params = {
            "algorithm": algorithm,
            "username": username,
            "salt": salt,
        }
        a = """
           60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD
           DA2D4393
        """
        a = a.replace(" ", "").replace("\n", "").decode("hex")
        a = int_from_bytes(a)
        b = """
           E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1
           05284D20
        """
        b = b.replace(" ", "").replace("\n", "").decode("hex")
        b = int_from_bytes(b)
        # Sanity-check algorithm paramters.
        (N, g, k, hashmod, _) = ALGORITHMS[algorithm]
        self.assertEquals(int_to_bytes(k).encode("hex").upper(),
                          "7556AA045AEF2CDD07ABAF0F665C3E818913186F")
        # Check calculation of x and v
        salted = salt + hashmod(username + ":" + password).digest()
        x = int_from_bytes(hashmod(salted).digest())
        self.assertEquals(int_to_bytes(x).encode("hex").upper(),
                          "94B7555AABE9127CC58CCF4993DB6CF84D16C124")
        v = calculate_verifier(params, password)
        v_expected = """
           7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
           9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
           C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
           EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
           E955A5E2 9E7AB245 DB2BE315 E2099AFB
        """
        self.assertEquals(int_to_bytes(v).encode("hex").upper(),
                          v_expected.replace(" ", "").replace("\n", ""))
        # Check calculation of A and B
        B = calculate_server_pubkey(params, b, v)
        B_expected = """
           BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
           BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
           6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
           37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
           EB4012B7 D7665238 A8E3FB00 4B117B58
        """
        self.assertEquals(int_to_bytes(B).encode("hex").upper(),
                          B_expected.replace(" ", "").replace("\n", ""))
        A = calculate_client_pubkey(params, a)
        A_expected = """
           61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
           4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
           8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
           BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
           B349EF5D 76988A36 72FAC47B 0769447B
        """
        self.assertEquals(int_to_bytes(A).encode("hex").upper(),
                          A_expected.replace(" ", "").replace("\n", ""))
        # Check calculation of shared secret
        params["ckey"] = b64encode(int_to_bytes(A))
        S = calculate_shared_secret(params, privkey=b, verifier=v)
        S_expected = """
           B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
           233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C
           41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F
           3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D
           C346D7E4 74B29EDE 8A469FFE CA686E5A
        """
        self.assertEquals(int_to_bytes(S).encode("hex").upper(),
                          S_expected.replace(" ", "").replace("\n", ""))
