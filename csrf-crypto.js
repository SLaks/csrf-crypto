/*jshint node: true, camelcase: true, eqeqeq: true, forin: true, immed: true, latedef: true, newcap: true, noarg: true, undef: true, globalstrict: true, laxbreak: true*/
"use strict";
var crypto = require('crypto');

var defaultAlgorithm = 'sha512',
	defaultCookieName = '_csrfKey',
	saltSize = 20,
	emptyUserData = function (req) { return ""; };

// These keys are used to transform the caller's master key
// into two separate keys for the cookie and form tokens.
var cookieKeyKey = new Buffer('55db309354097fca60732bf300f04e1880b285dcd506437c052e13d33313ada04c43f6cb613ae2a38affc693b4fbce3df7521eaf5ba200a2c95693f64f343fc5', 'hex');
var formKeyKey = new Buffer('6a23031b0b18777157cabf8aed626e298720115c2dbf4b73af790cda42fb4bdb2afd3d1909526b519c2bd5ccded109ddb0caef43b743329c6df2bb8ef49bec08', 'hex');

function base64Random(numBytes) {
	var bytes = crypto.randomBytes(numBytes);
	return new Buffer(bytes, 'binary').toString('base64');
}

function allowCsrf() {
	/*jshint validthis:true */
	this._csrfAllowed = true;
}

module.exports = function csrfCrypto(options) {
	if (!options || !options.key)
		throw new Error("csrf-crypto requires a key");

	options.algorithm = options.algorithm || defaultAlgorithm;

	var cookieName;
	if (typeof options.cookieName === 'function')
		cookieName = options.cookieName;
	else if (options.cookieName)
		cookieName = function (req) { return options.cookieName; };
	else
		cookieName = function (req) { return defaultCookieName; };

	var getUserData;
	if (!options.userData) {
		getUserData = emptyUserData;
	} else {
		// Since we use '|' to split parts, make sure that the userData
		// does not contain that character.
		getUserData = function (req) {
			return String(options.userData(req)).replace('|', '^');
		};
	}

	var cookieDomain;
	if (typeof options.domain === 'function')
		cookieDomain = options.domain;
	else if (options.domain)
		cookieDomain = function (req) { return options.domain; };
	else if (options.allowSubdomains)
		cookieDomain = function (req) { return req.host === 'localhost' ? void 0 : '.' + req.host; };	// Browsers don't like .localhost
	else
		cookieDomain = function (req) { };

	var cookieKey = crypto.createHmac(options.algorithm, options.key).update(cookieKeyKey).digest();
	var formKey = crypto.createHmac(options.algorithm, options.key).update(formKeyKey).digest();

	function checkSecure(req) {
		if (options.secure && !req.secure)
			throw new Error("csrf-crypto has been configured to require SSL; cannot call CSRF functions in non-HTTPS request to " + req.originalUrl);
	}

	// The cookie has three parts:
	// Random salt, userData (if any), and a hash of the previous two.
	// If the caller provided a userData() function, the userData from
	// the cookie will be checked against it during token verification

	// Private function that adds a new cookie token to the response and returns its salt value
	function createCookie(res) {
		var salt = base64Random(saltSize);

		var userData = getUserData(res.req);

		var hasher = crypto.createHmac(options.algorithm, cookieKey);
		hasher.update(salt);
		hasher.update("|");	// Don't confuse longer or shorter userData's
		hasher.update(userData);

		var hash = hasher.digest('base64');

		var cookie = salt + "|" + userData + "|" + hash;
		res.cookie(cookieName(res.req), cookie, {
			httpOnly: true,
			secure: options.secure,
			domain: cookieDomain(res.req)
		});
		return salt;
	}

	// Private function that finds an existing cookie token and returns its salt value
	function getCookieToken(res) {
		var value = res.req.cookies[cookieName(res.req)];
		if (!value)
			return false;

		var parts = value.split('|');

		// If the existing cookie is invalid, reject it.
		if (parts.length !== 3)
			return false;

		// If the user data doesn't match this request's user, reject the cookie
		if (parts[1] !== getUserData(res.req))
			return false;

		var hasher = crypto.createHmac(options.algorithm, cookieKey);
		hasher.update(parts[0]);
		hasher.update("|");	// Don't confuse longer or shorter userDatas
		hasher.update(parts[1]);

		// If the hash doesn't match, reject the cookie
		if (parts[2] !== hasher.digest('base64'))
			return false;

		return parts[0];
	}

	/**
	 * Clears the CSRF cookie token and removes any cached data.
	 * This function must be called on the response object.
	 * 
	 * @returns {String} An opaque token to include with new requests.
	 */
	function resetCsrf() {
		/*jshint validthis:true */
		this.clearCookie(cookieName(this.req), { domain: cookieDomain(this.req) });
		delete this._csrfFormToken;
	}
	/**
	 * Gets a new form token for the current response.
	 * This function must be called on the response object.
	 * 
	 * @returns {String} An opaque token to include with new requests.
	 */
	function getFormToken() {
		/*jshint validthis:true */
		if (this._csrfFormToken)
			return this._csrfFormToken;
		checkSecure(this.req);

		var cookieToken = getCookieToken(this) || createCookie(this);
		var salt = base64Random(saltSize);

		var hasher = crypto.createHmac(options.algorithm, cookieKey);
		hasher.update(cookieToken);
		hasher.update("|");
		hasher.update(salt);

		this._csrfFormToken = salt + "|" + hasher.digest('base64');
		return this._csrfFormToken;
	}

	/**
	 * Verifies a form token submitted with the current request.
	 * This function must be called on the request object.
	 * 
	 * @returns {Boolean} True if the form token matches the cookie in the request.
	 */
	function verifyFormToken(formToken) {
		/*jshint validthis:true */
		checkSecure(this);

		// If we already cached this token, we know that it's valid.
		// If we validate two different tokens for the same request,
		// this won't incorrectly skip the second one.
		if (this.res._csrfFormToken && this.res._csrfFormToken === formToken)
			return true;

		this._csrfChecked = true;
		if (!formToken) return false;

		var cookieToken = getCookieToken(this.res);
		if (!cookieToken) return false;

		var parts = formToken.split('|');

		// If the token is invalid, reject it.
		if (parts.length !== 2)
			return false;

		var hasher = crypto.createHmac(options.algorithm, cookieKey);
		hasher.update(cookieToken);
		hasher.update("|");	// Don't confuse longer or shorter tokens
		hasher.update(parts[0]);

		// If the hash doesn't match, reject the token
		if (parts[1] !== hasher.digest('base64'))
			return false;

		// If we have a valid token, reuse it for this request
		// instead of generating a new one. (saves crypto ops)
		if (!this.res._csrfFormToken)
			this.res._csrfFormToken = formToken;

		return true;
	}

	return function (req, res, next) {
		res.getFormToken = getFormToken;
		res.resetCsrf = resetCsrf;

		req.allowCsrf = allowCsrf;
		req.verifyToken = verifyFormToken;

		next();
	};
};

function error(code, msg) {
	var err = new Error(msg || require('http').STATUS_CODES[code]);
	err.status = code;
	return err;
}


function getFormToken(req) {
	// Copied from connect/csrf
	return (req.body && req.body._csrf)
		|| (req.query && req.query._csrf)
		|| (req.headers['x-csrf-token']);
}
var skipMethods = { GET: true, HEAD: true, OPTIONS: true };

function enforcerMiddleware(req, res, next) {
	if (!req.verifyToken)
		throw new Error("csrfCrypto.enforcer() must be use()d after csrfCrypto()");

	if (skipMethods.hasOwnProperty(req.method)) return next();

	// If an earlier middleware calls req.allowCsrf(), don't verify
	if (req._csrfAllowed) return next();

	if (!req.verifyToken(getFormToken(req)))
		return next(error(403));

	next();
}
module.exports.enforcer = function () { return enforcerMiddleware; };


function guardMiddleware(req, res, next) {
	var end = res.end;
	res.end = function (data, encoding) {
		if (!skipMethods.hasOwnProperty(req.method)
		&& !(req._csrfAllowed || req._csrfChecked))
			throw new Error(req.method + " request to " + req.originalUrl + " finished without CSRF verification");

		res.end = end;
		res.end(data, encoding);
	};
	next();
}
module.exports.guard = function () { return guardMiddleware; };