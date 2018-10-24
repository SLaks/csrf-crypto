# csrf-crypto
[![build status](https://secure.travis-ci.org/SLaks/csrf-crypto.png)](http://travis-ci.org/SLaks/csrf-crypto)

csrf-crypto implements CSRF protection without using server-side session, just like ASP.Net's [AntiForgery class](http://msdn.microsoft.com/en-us/library/system.web.helpers.antiforgery.aspx).

As such, it can be used in web farm scenarios without requiring that each user stick to one machine or that the machines can communicate with eachother.  
It still prevents attackers from generating valid form tokens even if they can read the victim's cookies.

To do this, it utilizes a secret key that is shared by all of the servers.

## Replacing Connect's CSRF
**Unlike the connect's built-in csrf module, you must verify the tokens in csrf-crypto explicitly in each POST request.**  
Alternatively, you can use the optional csrfCrypto.enforcer() middleware to make it behave exactly like `csrf`:

```js
expressApp.use(csrfCrypto({ key: secret }));
expressApp.use(csrfCrypto.enforcer());
```

You will still need to replace `req.session._csrf` with `res.getFormToken()`.

# Usage

First, install the middleware:

```js
expressApp.use(csrfCrypto({ key: secret }));
```

When returning a `<form>`, get a form token for the response:

```js
var formToken = res.getFormToken();
```
```html
<input type="hidden" name="_csrf" value="{{formToken}}" />
```

Finally, in the POST handler, verify the token for the request:
```js
if (!req.verifyToken(req.body._csrf)) {
	// No! Bad boy!
}
```

To force the cookie to be regenerated, call `res.resetCsrf()` before calling `getFormToken()`.  This method will remove the current cookie and clear any cached validity information.  
This method should be called in conjunction with the `userData()` option to regenerate the cookie of the user changes (eg, after logging in).

# Helper Middleware

If you don't want to manually verify the token in every POST, you have two options:

### `csrfCrypto.enforcer()`
This middleware will verify the CSRF token for all incoming POST (or PUT, or anything except GET, HEAD, and OPTIONS) requests, just like the standard [csrf middleware](http://www.senchalabs.org/connect/csrf.html).  Like the standard middleware, it will look for the form token in a `_csrf` field in the body or querystring, or in the `X-CSRF-Token` header field.  If the token is missing or invalid, it will send an HTTP 403 error.

An earlier middleware can call `req.allowCsrf();` to suppress the verification.

This middleware must be included after csrfCrypto itself, but before any middleware that needs to be protected against CSRF attacks:
```js
expressApp.use(csrfCrypto({ key: secret }));
expressApp.use(csrfCrypto.enforcer());
```

### `csrfCrypto.guard()`
This middleware will make sure that you don't forget to verify any non-GET (nor HEAD, nor OPTIONS) requests against CSRF.

If neither `req.verifyToken()` nor `req.allowCsrf()` has been called on such a request, `res.end()` will throw an exception.

This middleware does not verify that the result of `req.verifyToken()` has been acted upon.

This middleware takes no options and must be included before any middleware that might end the request.  (it does not need to be after csrfCrypto)


# Options
The csrfCrypto middleware function takes an options hash with the following options.  
All options except `key` are optional.

 - `key`: The HMAC key used to sign tokens.  This should be a Node.JS `Buffer` object containing at least as many bytes as your algorithm's key size, from a secure random number generator.  This key should be replaced periodically.
 - `algorithm`: The HMAC hash algorithm to use.  Must be supported by `crypto.createHmac()`.  Defaults to `sha512`.
 - `cookieName`: The name of the cookie to store the cookie token in  Defaults to `_csrfKey`.  
  This can also be a function, in which case it will be called with the connect `req` object as a parameter whenever creating or deleting a cookie.  
For example, this can be used to make different groups of SSL-wildcarded subdomains share different CSRF cookies set on the parent domain.
 - `secure`: True to require HTTPS everywhere (setting the Secure flag on the cookie to prevent insecure transmission).  Defaults to false.  If true, calling CSRF functions in a non-HTTPS request will throw an exception.
 - `userData`: A `function(req)` that returns a string unique to the current user, to be included in the cookie token.  This prevents users from using other users' token pairs.  The return value of this function is inserted as plain text into the cookie; it must return printable ASCII characters and should not return confidential information.  The function is passed the connect `req` object.
 - `domain`: Specifies the CSRF cookies' `domain` header.  This can be a string, or a function that takes the `req` and returns a string.  If a function is specified, it will be invoked (with no `this`) whenever the CSRF cookie is created or deleted.
 - `allowSubdomains`: If true, CSRF cookies will be set on <code>.<i>example.com</i></code> (where `example.com` is the HTTP `Host` header, minus the port number), allowing them to be inherited by subdomains.  Use with caution; this allows attackers who control any subdomain of your domain name to steal users' tokens.   This option has no effect on localhost, or if `domain` is set.

# Security Guarantees
As long as the server-side key is kept secret, an attacker will not be able to derive a valid form token from an existing cookie token.

An attacker with write access to the victim's cookies will be able to get a form/cookie token pair directly from the server, and replace the victim's CSRF cookie with the attacker's.

This risk can be mitigated by providing a `userData()` function.  This will cause the attacker's token pair to fail when used by the victim unless the attacker can send a request as that user to grab the victim's token pair.

If the server-side key is exposed, an attacker with read access to the victim's cookies will be able to use the key to generate a valid form token from the cookie token.  
Exposing the server-side key will still maintain defense against attackers without any cookie read access.

# License
MIT
