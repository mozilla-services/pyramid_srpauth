pyramid_srpauth
===============

This is an authentication policy for __pyramid__ that verifies credentials
using the HTTP-SRP-HMAC-Auth protocol.

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
