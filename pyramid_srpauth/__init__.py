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
#   Ryan Kelly (rfkelly@mozilla.com)
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

A Pyramid plugin for authentication via HTTP-SRP-HMAC-Auth.

Never heard of it?  That's because it's not a standard protocol.  It's quite
similar to the standard HTTP-Digest-Auth protocol:

    http://tools.ietf.org/html/rfc2617

But it uses the Secure Remote Password Protocol so that compromising the
server database does not immediately compromise everyone's credentials:

    http://srp.stanford.edu/
    http://www.ietf.org/rfc/rfc2945.txt

The details of the protocol are based on a draft spec from Robert Sayre:

    https://bug356855.bugzilla.mozilla.org/attachment.cgi?id=269128

However, the following changes have been made to enhance security:

    * calculate x according to TLS-SRP (RFC-5054) rather than trying to
      use an existing database of password hashes.  This will discourage
      people from using SRP as a symmetric protocol and unwittingly
      decreasing its security.

    * use a nonce-count as per RFC-2617, to help prevent replay attacks.

    * send the public key values in the Authorization header, not as
      separate headers.

"""

import hashlib
from base64 import b64encode

from zope.interface import implements

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Everyone, Authenticated
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.response import Response
from pyramid.util import DottedNameResolver

from pyramid_srpauth.noncemanager import SignedNonceManager
from pyramid_srpauth.parseauthz import parse_authz_header
from pyramid_srpauth.utils import (validate_parameters,
                                   validate_uri,
                                   validate_nonce,
                                   calculate_verifier,
                                   calculate_server_pubkey,
                                   check_response,
                                   int_from_bytes,
                                   int_to_bytes)


# WSGI environ key used to indicate a stale nonce.
_ENVKEY_STALE_NONCE = "pyramid_srpauth.stale_nonce"

# WSGI environ key used to cache a validated digest response.
_ENVKEY_VALID_RESPONSE = "pyramid_srpauth.valid_response"


class SRPAuthenticationPolicy(object):
    """A pyramid plugin for authentication via HTTP-SRP-HMAC-Auth.

    This plugin provides a pyramid IAuthenticationPolicy implementing a scheme
    inspired by HTTP-Digest-Auth, but using SRP keys and HMAC digests:

        http://tools.ietf.org/html/rfc2617
        http://srp.stanford.edu/
        http://www.ietf.org/rfc/rfc2945.txt

    To implement nonce generation, storage and expiration, this class
    uses a helper object called a "nonce manager".  This allows the details
    of nonce management to be modified to meet the security needs of your
    deployment.  The default implementation (SignedNonceManager) should be
    suitable for most purposes.
    """

    implements(IAuthenticationPolicy)

    def __init__(self, realm, nonce_manager=None, domain=None, algorithm=None,
                 get_password=None, get_verifier=None, groupfinder=None):
        if nonce_manager is None:
            nonce_manager = SignedNonceManager()
        if algorithm is None:
            algorithm = "SRP-1024-SHA1"
        self.realm = realm
        self.nonce_manager = nonce_manager
        self.domain = domain
        self.algorithm = algorithm
        self.get_password = get_password
        self.get_verifier = get_verifier
        self.groupfinder = groupfinder

    @classmethod
    def from_settings(cls, settings={}, prefix="srpauth.", **kwds):
        """Create a new SRPAuthenticationPolicy from a settings dict."""
        # Grab out all the settings keys that start with our prefix.
        auth_settings = {}
        for name, value in settings.iteritems():
            if not name.startswith(prefix):
                continue
            auth_settings[name[len(prefix):]] = value
        # Update with any additional keyword arguments.
        auth_settings.update(kwds)
        # Now look for specific keys of interest.
        maybe_resolve = DottedNameResolver(None).maybe_resolve
        # You must specify a realm.
        if "realm" not in auth_settings:
            raise ValueError("pyramid_srpauth: you must specify the realm")
        # NonceManager can be specified as class or instance name.
        nonce_manager = maybe_resolve(auth_settings.get("nonce_manager"))
        if callable(nonce_manager):
            nonce_manager = nonce_manager()
        auth_settings["nonce_manager"] = nonce_manager
        # get_password can be dotted name of a callable
        get_password = maybe_resolve(auth_settings.get("get_password"))
        if get_password is not None:
            assert callable(get_password)
        auth_settings["get_password"] = get_password
        # get_verifier can be dotted name of a callable
        get_verifier = maybe_resolve(auth_settings.get("get_verifier"))
        if get_verifier is not None:
            assert callable(get_verifier)
        auth_settings["get_verifier"] = get_verifier
        # groupfinder can be dotted name of a callable
        groupfinder = maybe_resolve(auth_settings.get("groupfinder"))
        if groupfinder is not None:
            assert callable(groupfinder)
        auth_settings["groupfinder"] = groupfinder
        # OK, the rest should just be keyword arguments.
        return cls(**auth_settings)

    def authenticated_userid(self, request):
        """Get the authenticated userid for this request.

        When using HTTP-SRP-HMAC-Auth, this requires calculating the expected
        digest response using the user's nonce and password verifier, and
        comparing it to the response returned in the Authorization header.
        """
        params = self._get_auth_params(request)
        if params is None:
            return None
        if not self._authenticate(request, params):
            return None
        username = params["username"]
        if self.groupfinder is not None:
            if self.groupfinder(username) is None:
                return None
        return username

    def unauthenticated_userid(self, request):
        """Get the unauthenticated userid for this request.

        When using HTTP-SRP-HMAC-Auth, this involves looking in the HTTP
        Authorization header to find the reported username.
        """
        params = self._get_auth_params(request)
        if params is None:
            return None
        return params.get("username")

    def effective_principals(self, request):
        """Get the list of effective principals for this request."""
        principals = [Everyone]
        params = self._get_auth_params(request)
        if params is None:
            return principals
        if not self._authenticate(request, params):
            return principals
        username = params["username"]
        if self.groupfinder is None:
            groups = ()
        else:
            groups = self.groupfinder(username)
            if groups is None:
                return principals
        principals.append(username)
        principals.append(Authenticated)
        principals.extend(groups)
        return principals

    def remember(self, request, principal, **kw):
        """Remember the authenticated identity.

        This method can be used to pre-emptively send an updated nonce to
        the client as part of a successful response.  It is otherwise a
        no-op; the user-agent is supposed to remember the provided credentials
        and automatically send an authorization header with future requests.
        """
        params = self._get_auth_params(request)
        if params is None:
            return None
        nonce = params["nonce"]
        next_nonce = self.nonce_manager.get_next_nonce(nonce, request)
        if next_nonce is None:
            return None
        new_params = self._get_challenge_params(request, params, next_nonce)
        value = 'nextnonce="%s", nextskey="%s"'
        value = value % (next_nonce, new_params["skey"])
        return [("Authentication-Info", value)]

    def forget(self, request):
        """Forget the authenticated identity.

        For digest auth this is equivalent to sending a new challenge header,
        which should cause the user-agent to re-prompt for credentials.
        """
        return self._get_challenge_headers(request, check_stale=False)

    def challenge_view(self, request):
        """View that challenges for credentials with a "401 Unauthorized".

        This method can be used as a pyramid "forbidden view" in order to
        challenge for auth credentials when necessary.
        """
        headerlist = [("Content-Type", "text/plain")]
        headerlist.extend(self._get_challenge_headers(request))
        return Response("Unauthorized", status="401 Unauthorized",
                        headerlist=headerlist)

    def _get_challenge_headers(self, request, check_stale=True):
        """Get headers necessary for a fresh srp-hmac-auth challenge.

        This method generates a new srp-hmac-auth challenge for the given
        request, including a fresh nonce.  If the environment is marked
        as having a stale nonce then this is indicated in the challenge.
        """
        params = {}
        params["realm"] = self.realm
        if self.domain is not None:
            params["domain"] = self.domain
        # Escape any special characters in those values, so we can send
        # them as quoted-strings.  The extra values added below are under
        # our control so we know they don't contain quotes.
        for key, value in params.iteritems():
            params[key] = value.replace('"', '\\"')
        # Add a fresh set of challenge parameters.
        params.update(self._get_challenge_params(request))
        # Mark the nonce as stale if told so by the environment.
        if check_stale and request.environ.get(_ENVKEY_STALE_NONCE):
            params["stale"] = "TRUE"
        # Construct the final header as quoted-string k/v pairs.
        value = ", ".join('%s="%s"' % itm for itm in params.iteritems())
        return [("WWW-Authenticate", "SRP-HMAC " + value)]

    def _get_unvalidated_auth_params(self, request):
        """Extract srp-hmac-auth parameters from the request.

        This method extracts srp-hmac-auth parameters from the Authorization
        header and returns them as a dict.  If they are missing then None
        is returned.
        """
        try:
            params = parse_authz_header(request)
        except ValueError:
            params = None
        if params is None:
            return None
        if params["scheme"].lower() != "srp-hmac":
            return None
        return params

    def _get_auth_params(self, request):
        """Extract srp-hmac-auth parameters from the request.

        This method extracts srp-hmac-auth parameters from the Authorization
        header and returns them as a dict.  If they are missing then None
        is returned.
        """
        params = self._get_unvalidated_auth_params(request)
        if params is None:
            return None
        # Check that they're valid srp-hmac-auth parameters.
        if not validate_parameters(params, self.realm):
            return None
        # Check that the digest is applied to the correct URI.
        if not validate_uri(request, params):
            return None
        # Check that the provided nonce is valid.
        # If this looks like a stale request, mark it in the request
        # so we can include that information in the challenge.
        if not validate_nonce(self.nonce_manager, request, params):
            request.environ[_ENVKEY_STALE_NONCE] = True
            return None
        return params

    def _authenticate(self, request, params):
        """Authenticate srp-hmac-auth params against known passwords.

        This method checks the provided response digest to authenticate the
        request, using either the "get_password" or "get_verifier" callback
        to obtain the user's verifier.
        """
        username = params["username"]
        # Quick check if we've already validated these params.
        if request.environ.get(_ENVKEY_VALID_RESPONSE):
            return True
        # Obtain the verifier information somehow.
        (_, _, verifier) = self._get_verifier(username)
        if verifier is None:
            return False
        # Validate the HMAC digest response.
        privkey = self._get_privkey(params["nonce"])
        if not check_response(request, params,
                              privkey=privkey, verifier=verifier):
            return False
        # Cache the successful authentication.
        request.environ[_ENVKEY_VALID_RESPONSE] = True
        return True

    def _get_verifier(self, username):
        """Obtain the password verifier data to use for the given user.

        This method returns a tuple (algorithm, salt, verifier) giving
        the necessary information to verify the user's password.  If no
        information is available for the user then a tuple of Nones is
        returned.
        """
        #  If we have a get_verifier callback, use it directly.
        if self.get_verifier is not None:
            verifier = self.get_verifier(username)
            if verifier is not None and verifier[0] is not None:
                return verifier
        #  Otherwise, we need to calculate it from the password.
        if self.get_password is not None:
            password = self.get_password(username)
            if password is not None:
                algorithm = "SRP-1024-SHA1"
                salt = hashlib.sha1(username + self.realm).hexdigest()[:8]
                verifier = calculate_verifier({
                    "username": username,
                    "algorithm": algorithm,
                    "salt": salt,
                }, password)
                return (algorithm, salt, verifier)
        # If that didn't work out, they have no verifier.
        return (None, None, None)

    def _get_challenge_params(self, request, params=None, nonce=None):
        """Generate a fresh set of challenge parameters."""
        # Parse the parameters from the incoming request.
        # We're only looking for username, so don't bother validating
        # any other parameters that may be present.
        if params is None:
            params = parse_authz_header(request)
            if params is None:
                return {}
        # If they didn't provide the username, they get a blank challenge.
        # This is the first request in the handshake.
        username = params.get("username")
        if username is None:
            return {}
        # If they did provide the username, then they need to know the
        # salt, server-side key, etc.  This is the second request.
        (algorithm, salt, verifier) = self._get_verifier(username)
        if verifier is None:
            return {}
        new_params = {}
        new_params["algorithm"] = algorithm
        new_params["salt"] = salt
        # Generate new nonce if needed
        if nonce is None:
            nonce = self.nonce_manager.generate_nonce(request)
        new_params["nonce"] = nonce
        # Calculate the corresponding server public key.
        privkey = self._get_privkey(nonce)
        pubkey = calculate_server_pubkey(params, privkey, verifier)
        new_params["skey"] = b64encode(int_to_bytes(pubkey))
        # That'll do it.
        return new_params

    def _get_privkey(self, nonce):
        """Get the server-side private key for a given nonce."""
        privkey = self.nonce_manager.get_prandom_bytes(nonce, 32)
        return int_from_bytes(privkey)


def includeme(config):
    """Include default srpauth settings into a pyramid config.

    This function provides a hook for pyramid to include the default settings
    for HTTP-SRP-HMAC-Auth.  Activate it like so:

        config.include("pyramid_srpauth")

    This will activate a SRPAuthenticationplicy instance with settings taken
    from the the application settings as follows:

        * srpauth.realm:           realm string for auth challenge header
        * srpauth.nonce_manager:   name of NonceManager class to use
        * srpauth.domain:          domain string for auth challenge header
        * srpauth.get_password:    name of password-retrieval function
        * srpauth.get_verifier:    name of verifier-retrieval function
        * srpauth.groupfinder:     name of group-finder callback function

    It will also activate:

        * a forbidden view that will challenge for srp-hmac-auth credentials.

    """
    # Grab the pyramid-wide settings, to look for any auth config.
    settings = config.get_settings().copy()
    # Use the settings to construct an AuthenticationPolicy.
    authn_policy = SRPAuthenticationPolicy.from_settings(settings)
    config.set_authentication_policy(authn_policy)
    # Hook up a default AuthorizationPolicy.
    # You can't have one without the other, and  ACLAuthorizationPolicy is
    # usually what you want.  If the app configures one explicitly then this
    # will get overridden.
    authz_policy = ACLAuthorizationPolicy()
    config.set_authorization_policy(authz_policy)
    # Add forbidden view to challenge for auth credentials.
    config.add_view(authn_policy.challenge_view,
                    context="pyramid.exceptions.Forbidden")
