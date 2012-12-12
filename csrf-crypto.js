/*jshint node: true, camelcase: true, eqeqeq: true, forin: true, immed: true, latedef: true, newcap: true, noarg: true, undef: true, globalstrict: true*/
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

module.exports = function csrfCrypto(options) {
	if (!options || !options.key)
		throw new Error("csrf-crypto requires a key");

	options.algorithm = options.algorithm || defaultAlgorithm;
	options.cookieName = options.cookieName || defaultCookieName;

	var getUserData;
	if (!options.userData) {
		getUserData = emptyUserData;
	} else {
		// Since we use '|' to split parts, make sure that the userData
		// does not contain that character.
		getUserData = function (req) {
			return options.userData(req).replace('|', '^');
		};
	}

	var cookieKey = crypto.createHmac(options.algorithm, options.key).update(cookieKeyKey).digest();
	var formKey = crypto.createHmac(options.algorithm, options.key).update(formKeyKey).digest();

	//TODO: options.secure

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
		res.cookie(options.cookieName, cookie, {});
		return salt;
	}

	// Private function that finds an existing cookie token and returns its salt value
	function getCookieToken(res, createIfMissing) {
		if (!res.req.cookies[options.cookieName])
			return false;

		var parts = res.req.cookies[options.cookieName].split('|');

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
	 * Gets a new form token for the current response.
	 * This function must be called on the response object.
	 * 
	 * @returns {String} An opaque token to include with new requests.
	 */
	function getFormToken() {
		/*jshint validthis:true */

		var cookieToken = getCookieToken(this) || createCookie(this);
		var salt = base64Random(saltSize);

		var hasher = crypto.createHmac(options.algorithm, cookieKey);
		hasher.update(cookieToken);
		hasher.update("|");
		hasher.update(salt);

		return salt + "|" + hasher.digest('base64');
	}

	/**
	 * Verifies a form token submitted with the current request.
	 * This function must be called on the request object.
	 * 
	 * @returns {Boolean} True if the form token matches the cookie in the request..
	 */
	function verifyFormToken(formToken) {
		/*jshint validthis:true */

		this.csrfChecked = true;
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

		return parts[1] === hasher.digest('base64');
	}

	return function (req, res, next) {
		res.getFormToken = getFormToken;

		req.verifyToken = verifyFormToken;

		next();
	};
};

//TODO: csrf.enforcer, csrf.autoChecker