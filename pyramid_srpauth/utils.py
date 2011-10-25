# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is pyramid_srpauth
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (rkelly@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
"""

Helper functions for pyramid_srpauth.

"""

import hmac
import hashlib
import wsgiref.util
from collections import deque
from urlparse import urlparse
from base64 import b64encode, b64decode

from pyramid_srpauth.parseauthz import parse_authz_header


# Algorithm definitions.
# These numbers are taken from the group parameters in RFC-5054.
ALGORITHMS = {
    "SRP-1024-SHA1": ("""
          EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
          9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
          8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
          7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
          FD5138FE 8376435B 9FC61D2F C0EB06E3
          """, 2, hashlib.sha1),
    "SRP-1536-SHA1": ("""
          9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961
          4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843
          80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B
          E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5
          6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A
          F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E
          8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB
          """, 2, hashlib.sha1),
    "SRP-2048-SHA1": ("""
          AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
          3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
          CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
          D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
          7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
          436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
          5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
          03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
          94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
          9E4AFF73
          """, 2, hashlib.sha1),
}


DEFAULT_ALGORITHM = "SRP-1024-SHA1"


def int_to_bytes(n):
    """Convert an integer into some bytes"""
    if n == 0:
        return "\x00"
    # Trick: use a deque to collect digits in reverse order.
    # This allows us to use an efficent "".join() without reversing a list
    digits = deque()
    while n > 0:
        rem = n % 256
        digits.appendleft(chr(rem))
        n = n / 256
    return "".join(digits)


def int_from_bytes(data):
    """Convert some bytes into an integer."""
    return int(data.encode("hex"), 16)


# Now we can process each algorithm to pre-calculate other useful info.
# Use a private function to avoid polluting global namespace.
def _process_algorithms():
    for name, (N, g, hashmod) in ALGORITHMS.iteritems():
        N = int(N.replace(" ", "").replace("\n", ""), 16)
        # This construction of k is taken from RFC-5054.
        N_str = int_to_bytes(N)
        padlen = len(N_str)
        g_str = int_to_bytes(g).rjust(padlen, "\x00")
        k = int_from_bytes(hashmod(N_str + g_str).digest())
        ALGORITHMS[name] = (N, g, k, hashmod, padlen)

_process_algorithms()
del _process_algorithms


def validate_parameters(params, realm=None):
    """Validate the given dict of srp-hmac-auth parameters.

    This function allows you to sanity-check srp-hmac-auth parameters, to
    make sure that all required information has been provided.  It returns
    True if the parameters are a well-formed srp-hmac-auth response, False
    otherwise.
    """
    # Check for required information.
    REQUIRED_KEYS = ("username", "realm", "nonce", "uri", "response",
                     "ckey", "nc", "algorithm")
    for key in REQUIRED_KEYS:
        if key not in params:
            return False
    if realm is not None and params["realm"] != realm:
        return False
    # Check that the algorithm is known.
    if params["algorithm"] not in ALGORITHMS:
        return False
    # Looks good!
    return True


def validate_uri(request, params=None):
    """Validate that the digest URI matches the request environment.

    This is a helper function to check that srp-hmac-auth is being applied
    to the correct URI.  It matches the given request environment against
    the URI specified in the srp-hmac auth parameters, returning True if
    they are equiavlent and False otherwise.
    """
    if params is None:
        params = parse_authz_header(request)
    uri = params["uri"]
    req_uri = wsgiref.util.request_uri(request.environ)
    if uri != req_uri:
        p_req_uri = urlparse(req_uri)
        if not p_req_uri.query:
            if uri != p_req_uri.path:
                return False
        else:
            if uri != "%s?%s" % (p_req_uri.path, p_req_uri.query):
                return False
    return True


def validate_nonce(nonce_manager, request, params=None):
    """Validate that the auth parameters contain a fresh nonce.

    This is a helper function to check that the provided srp-hmac-auth
    credentials contain a valid, up-to-date nonce.  It calls various
    methods on the provided NonceManager object in order to query and
    update the state of the nonce database.

    Returns True if the nonce is valid, False otherwise.
    """
    if params is None:
        params = parse_authz_header(request)
    # Check that the nonce itself is valid.
    nonce = params["nonce"]
    if not nonce_manager.is_valid_nonce(nonce, request):
        return False
    # Check that the nonce-count is valid.
    # RFC-2617 says the nonce-count must be an 8-char-long hex number.
    # We convert to an integer since they take less memory than strings.
    # We enforce the length limit strictly since flooding the server with
    # many large nonce-counts could cause a DOS via memory exhaustion.
    nc_new = params.get("nc", None)
    if nc_new is not None:
        try:
            nc_new = int(nc_new[:8], 16)
        except ValueError:
            return False
    # Check that the the nonce-count is strictly increasing.
    nc_old = nonce_manager.get_nonce_count(nonce)
    if nc_old is not None:
        if nc_new is None or nc_new <= nc_old:
            return False
    if nc_new is not None:
        nonce_manager.set_nonce_count(nonce, nc_new)
    # Looks good!
    return True


def calculate_pwdhash(params, password):
    """Calculate the password hash (aka "x") for the given params."""
    hashmod = ALGORITHMS[params.get("algorithm", DEFAULT_ALGORITHM)][3]
    pwdhash = hashmod(params["username"] + ":" + password).digest()
    return int_from_bytes(hashmod(params["salt"] + pwdhash).digest())


def calculate_verifier(params, password):
    """Calculate the SRP password verifier from the given params."""
    pwdhash = calculate_pwdhash(params, password)
    N, g = ALGORITHMS[params.get("algorithm", DEFAULT_ALGORITHM)][:2]
    return pow(g, pwdhash, N)


def calculate_server_pubkey(params, privkey, verifier):
    """Calculate the server-side public key (aka "B" or "skey")."""
    N, g, k = ALGORITHMS[params.get("algorithm", DEFAULT_ALGORITHM)][:3]
    return ((k * verifier) + pow(g, privkey, N)) % N


def calculate_client_pubkey(params, privkey):
    """Calculate the client-side public key (aka "A" or "ckey")."""
    N, g = ALGORITHMS[params.get("algorithm", DEFAULT_ALGORITHM)][:2]
    return pow(g, privkey, N)


def calculate_multiplier(params):
    """Calculate the multipler (aka "u") from the given params.

    This calculation pads the pubkeys to the length of the modulus then
    hashes them together.  It's taken from RFC-5054.
    """
    hashmod, padlen = ALGORITHMS[params.get("algorithm", DEFAULT_ALGORITHM)][3:]
    ckey = int_from_bytes(b64decode(params["ckey"]))
    skey = int_from_bytes(b64decode(params["skey"]))
    A_str = int_to_bytes(ckey).rjust(padlen, "\x00")
    B_str = int_to_bytes(skey).rjust(padlen, "\x00")
    return int_from_bytes(hashmod(A_str + B_str).digest())


def calculate_shared_secret(params, privkey, password=None, verifier=None):
    """Calculate the shared secret from the given data."""
    if "ckey" not in params:
        assert password is not None
        ckey = calculate_client_pubkey(params, privkey)
        params["ckey"] = b64encode(int_to_bytes(ckey))
    if "skey" not in params:
        assert verifier is not None
        skey = calculate_server_pubkey(params, privkey, verifier)
        params["skey"] = b64encode(int_to_bytes(skey))
    u = calculate_multiplier(params)
    N, g, k = ALGORITHMS[params.get("algorithm", DEFAULT_ALGORITHM)][:3]
    if password is not None:
        a = privkey
        B = int_from_bytes(b64decode(params["skey"]))
        x = calculate_pwdhash(params, password)
        secret = pow(B - (k * pow(g, x, N)), a + (u * x), N)
    else:
        A = int_from_bytes(b64decode(params["ckey"]))
        b = privkey
        v = verifier
        secret = pow(A * pow(v, u, N), b, N)
    return secret


def calculate_request_hmac(request, params=None, **kwds):
    """Calculate the expected HMAC for the given request.

    This function calculates the HMAC of the given request, using parameters
    from the request or from the optional "params" dict.  For client-side
    calculation you must provide "privkey" and "password" as keyword args;
    for server-side calculation you must provide "privkey" and "verifier".
    """
    if params is None:
        params = parse_authz_header(request)
    hashmod = ALGORITHMS[params.get("algorithm", DEFAULT_ALGORITHM)][3]
    secret = int_to_bytes(calculate_shared_secret(params, **kwds))
    hasher = hmac.new(secret, "", hashmod)
    # The hash covers: ckey, skey, nonce, nc, method, uri, headers.
    # They must all be as they will appear on the wire, i.e. SRP integers
    # in b64 encoding, other bytestrings in hex.
    hasher.update(params["ckey"])
    hasher.update(":")
    hasher.update(params["skey"])
    hasher.update(":")
    hasher.update(params["nonce"])
    hasher.update(":")
    hasher.update(params["nc"])
    hasher.update(":")
    hasher.update(request.method)
    hasher.update(":")
    hasher.update(params["uri"])
    hasher.update(":")
    hasher.update(request.environ.get("HTTP_CONTENT_TYPE", ""))
    hasher.update(":")
    hasher.update(request.environ.get("HTTP_CONTENT_LENGTH", ""))
    hasher.update(":")
    hasher.update(request.environ.get("HTTP_CONTENT_MD5", ""))
    # The output is also as on the wire, i.e. hex format.
    return hasher.hexdigest()


def check_response(request, params=None, **kwds):
    """Check if the given srp-hmac response is valid.

    This function checks whether a dict of srp-hmac response parameters
    has been correctly authenticated.  For client-side calculation you
    must provide "privkey" and "password" as keyword args; for server-side
    calculation you must provide "privkey" and "verifier".
    """
    expected = calculate_request_hmac(request, params, **kwds)
    # Use a timing-invarient comparison to prevent guessing the correct
    # hmac one character at a time.  Ideally we would reject repeated
    # attempts to use the same nonce, but that may not be possible using
    # e.g. time-based nonces.  This is a nice extra safeguard.
    return not strings_differ(expected, params["response"])


def strings_differ(string1, string2):
    """Check whether two strings differ while avoiding timing attacks.

    This function returns True if the given strings differ and False
    if they are equal.  It's careful not to leak information about *where*
    they differ as a result of its running time, which can be very important
    to avoid certain timing-related crypto attacks:

        http://seb.dbzteam.org/crypto/python-oauth-timing-hmac.pdf

    """
    if len(string1) != len(string2):
        return True
    invalid_bits = 0
    for a, b in zip(string1, string2):
        invalid_bits += a != b
    return invalid_bits != 0
