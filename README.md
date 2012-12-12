#csrf-crypto

csrf-crypto implements CSRF protection without using server-side session.

As such, it can be used in web farm scenarios without requiring that each user stick to one machine or that the machines can communicate with eachother.  
It still prevents attackers from generating valid form tokens even if they can read the victim's cookies.

To do this, it utilizes a secret key that is shared by all of the servers.

Unlike the connect's built-in csrf module, you must verify the tokens in csrf-crypto explicitly in each POST request.

#Options
The csrfCrypto middleware function takes an options hash with the following options.  
All options except `key` are optional.

 - `key`: The HMAC key used to sign tokens.  This should be a Node.JS `Buffer` object containing at least as many bytes as your algorithm's key size, from a secure random number generator.  This key should be replaced periodically.
 - `algorithm`: The HMAC hash algorithm to use.  Must be supported by `crypto.createHmac()`.  Defaults to `sha512`.
 - `cookieName`: The name of the cookie to store the cookie token in  Defaults to `_csrfKey`.
 - `secure`: True to require HTTPS everywhere (setting the Secure flag on the cookie to prevent insecure transmission).  Defaults to false.  If true, calling CSRF functions in a non-HTTPS request will throw an exception.
 - `userData`: A function that returns data unique to the current user, to be included in the cookie token.  This prevents users from using other users' token pairs.  The return value of this function is inserted as plain text into the cookie; it must return printable ASCII characters and should not return confidential information.  The function is passed the connect `req` object.

#Security Guarantees
As long as the server-side key is kept secret, an attacker will not be able to derive a valid form token from an existing cookie token.

An attacker with write access to the victim's cookies will be able to get a form/cookie token pair directly from the server, and replace the victim's CSRF cookie with the attacker's.

This risk can be mitigated by providing a `userData()` function.  This will cause the attacker's token pair to fail when used by the victim unless the attacker can send a request as that user to grab the victim's token pair.

If the server-side key is exposed, an attacker with read access to the victim's cookies will be able to use the key to generate a valid form token from the cookie token.  
Exposing the server-side key will still maintain defense against attackers without any cookie read access.