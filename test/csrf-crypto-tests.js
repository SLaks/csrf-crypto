/*jshint node: true, camelcase: true, eqeqeq: true, forin: true, immed: true, latedef: true, newcap: true, noarg: true, undef: true, globalstrict: true*/
/*global describe:false, it:false */
"use strict";

var mocha = require("mocha");
var assert = require("assert");

var csrfCrypto = require('..');

function Session(csrfOptions) {
	this.middleware = csrfCrypto(csrfOptions);
	this.cookies = {};
}
Session.prototype.run = function (req) {
	//Mock as much of the response object as I need

	req.body = req.body || {};
	req.query = req.query || {};
	req.headers = req.headers || {};
	req.cookies = this.cookies;

	var res = req.res = req.res || {};
	res.req = req;
	res.cookies = res.cookies || {};
	res.cookieOptions = res.cookieOptions || {};
	res.cookie = res.cookie || function (name, value, options) {
		this.cookies[name] = value;
		this.cookieOptions[name] = options || {};
		req.cookies[name] = value;
	};
	res.clearCookie = function (name, options) {
		delete req.cookies[name];
	};
	res.end = function () { };

	this.middleware(req, res, function () { });

	return res;
};

function getUser(req) { return req.user; }

describe('#csrfCrypto', function () {
	it('should succeed under normal circumstances', function () {
		var session = new Session({ key: 'abc' });

		var res = session.run({});
		var formToken = res.getFormToken();
		assert.strictEqual(res.cookieOptions._csrfKey.httpOnly, true, "Token cookie should be HttpOnly");

		var req2 = {};
		session.run(req2);
		assert.ok(req2.verifyToken(formToken));
	});
	it('should reuse form tokens for the same request', function () {
		var session = new Session({ key: 'abc' });

		var res = session.run({});
		var formToken1 = res.getFormToken();
		var formToken2 = res.getFormToken();

		assert.strictEqual(formToken1, formToken2);
	});
	it('should reuse already-validated form tokens', function () {
		var session = new Session({ key: 'abc' });

		var res = session.run({});
		var formToken1 = res.getFormToken();
		assert.strictEqual(res.cookieOptions._csrfKey.httpOnly, true, "Token cookie should be HttpOnly");

		var req2 = {};
		var res2 = session.run(req2);
		assert.ok(req2.verifyToken(formToken1));

		var formToken2 = res2.getFormToken();
		assert.strictEqual(formToken2, formToken1);
	});
	it('should fail if cookie is removed', function () {
		var session = new Session({ key: 'abc' });

		var res = session.run({});
		var formToken = res.getFormToken();

		delete session.cookies._csrfKey;

		var req2 = {};
		session.run(req2);
		assert.ok(!req2.verifyToken(formToken));
	});

	it('should succeed if cookie is copied across instances', function () {
		var session1 = new Session({ key: 'abc' });

		var res = session1.run({});
		var formToken = res.getFormToken();

		var session2 = new Session({ key: 'abc' });
		session2.cookies._csrfKey = session1.cookies._csrfKey;

		var req2 = {};
		session2.run(req2);
		assert.ok(req2.verifyToken(formToken));
	});

	it('should fail if cookie is copied across instances with different keys', function () {
		var session1 = new Session({ key: 'abc' });

		var res = session1.run({});
		var formToken = res.getFormToken();

		var session2 = new Session({ key: 'def' });
		session2.cookies._csrfKey = session1.cookies._csrfKey;

		var req2 = {};
		session2.run(req2);
		assert.ok(!req2.verifyToken(formToken));
	});

	it('should work with users', function () {
		var session = new Session({ key: 'abc', userData: getUser });

		var res1 = session.run({ user: "2|SLaks" });
		var formToken = res1.getFormToken();

		var req2 = { user: "2|SLaks" };
		session.run(req2);
		assert.ok(req2.verifyToken(formToken));
	});

	it('should fail with different users', function () {
		var session = new Session({ key: 'abc', userData: getUser });

		var res = session.run({ user: "1|izs" });
		var formToken = res.getFormToken();

		var req2 = { user: "2|SLaks" };
		session.run(req2);
		assert.ok(!req2.verifyToken(formToken));
	});

	it('should work across user change if resetCsrf() is called', function () {
		var session = new Session({ key: 'abc', userData: getUser });

		var res1 = session.run({});
		var formToken = res1.getFormToken();

		var req2 = {};
		var res2 = session.run(req2);
		assert.ok(req2.verifyToken(formToken));

		req2.user = "2|SLaks";	// User logged in; needs different token
		res2.resetCsrf();

		formToken = res2.getFormToken();

		var req3 = { user: "2|SLaks" };
		session.run(req3);
		assert.ok(req3.verifyToken(formToken));
	});


	it('should fail if cookie is copied across instances with & without users', function () {
		var session1 = new Session({ key: 'abc', userData: getUser });

		var res = session1.run({ user: "SLaks" });
		var formToken = res.getFormToken();

		var session2 = new Session({ key: 'abc' });
		session2.cookies._csrfKey = session1.cookies._csrfKey;

		var req2 = {};
		session2.run(req2);
		assert.ok(!req2.verifyToken(formToken));
	});

	it('should set secure cookies if requested', function () {
		var session = new Session({ key: 'abc', secure: true });

		var res = session.run({ secure: true });
		var formToken = res.getFormToken();
		assert.strictEqual(res.cookieOptions._csrfKey.secure, true, "Token Cookie should be secure");
	});

	it('should throw when getting token for HTTP if secure set', function () {
		var session = new Session({ key: 'abc', secure: true });

		var res = session.run({});
		assert.throws(function () {
			res.getFormToken();
		}, /HTTPS/i, "Didn't reject insecure token use");
	});

	it('should throw when verifying token for HTTP if secure set', function () {
		var session1 = new Session({ key: 'abc' });

		var res1 = session1.run({});
		var formToken = res1.getFormToken();

		var session2 = new Session({ key: 'abc', secure: true });
		session2.cookies._csrfKey = session1.cookies._csrfKey;

		var req2 = {};
		var res2 = session2.run(req2);

		assert.throws(function () {
			req2.verifyToken(formToken);
		}, /HTTPS/i, "Didn't reject insecure token use");
	});
});

describe('#csrfCrypto.enforcer', function () {
	function runEnforcer(res) {
		var retVal;
		csrfCrypto.enforcer()(res.req, res, function (arg) { retVal = arg; });
		return retVal;
	}

	it('should do nothing on GET requests', function () {
		var session = new Session({ key: 'abc' });

		var res = session.run({ method: 'GET' });
		var result = runEnforcer(res);
		assert.strictEqual(result, undefined);
	});
	it('should fail on tokenless POSTS', function () {
		var session = new Session({ key: 'abc' });

		var res = session.run({ method: 'POST' });
		var result = runEnforcer(res);
		assert.ok(result instanceof Error);
		assert.strictEqual(result.status, 403);
	});
	it('should fail on stolen tokens', function () {
		var session1 = new Session({ key: 'abc' });

		var res = session1.run({});
		var formToken = res.getFormToken();

		var session2 = new Session({ key: 'def' });
		session2.cookies._csrfKey = session1.cookies._csrfKey;

		var res2 = session2.run({ method: 'POST', body: { _csrf: formToken } });
		var result = runEnforcer(res2);
		assert.ok(result instanceof Error);
		assert.strictEqual(result.status, 403);
	});

	it('should accept form token in querystring', function () {
		var session = new Session({ key: 'abc' });

		var res1 = session.run({ method: 'GET' });
		var formToken = res1.getFormToken();

		var res2 = session.run({ method: 'POST', query: { _csrf: formToken } });
		var result = runEnforcer(res2);
		assert.strictEqual(result, undefined);
	});
	it('should accept form token in post', function () {
		var session = new Session({ key: 'abc' });

		var res1 = session.run({ method: 'GET' });
		var formToken = res1.getFormToken();

		var res2 = session.run({ method: 'POST', body: { _csrf: formToken } });
		var result = runEnforcer(res2);
		assert.strictEqual(result, undefined);
	});
	it('should accept form token in header', function () {
		var session = new Session({ key: 'abc' });

		var res1 = session.run({ method: 'GET' });
		var formToken = res1.getFormToken();

		var res2 = session.run({ method: 'POST', headers: { "x-csrf-token": formToken } });
		var result = runEnforcer(res2);
		assert.strictEqual(result, undefined);
	});
	it('should do nothing if allowCSRF is called', function () {
		var session = new Session({ key: 'abc' });

		var req = { method: 'POST' };
		var res = session.run(req);
		req.allowCsrf();
		var result = runEnforcer(res);
		assert.strictEqual(result, undefined);
	});
});
describe('#csrfCrypto.guard', function () {
	function runGuard(res) {
		var retVal;
		csrfCrypto.guard()(res.req, res, function () { });
		res.end();
	}

	it('should do nothing on GET requests', function () {
		var session = new Session({ key: 'abc' });

		var res = session.run({ method: 'GET' });
		runGuard(res);
	});
	it('should fail on non-validated POST request', function () {
		var session = new Session({ key: 'abc' });

		var res = session.run({ method: 'POST' });
		assert.throws(function () { runGuard(res); });
	});
	it('should do nothing if CSRF was allowed', function () {
		var session = new Session({ key: 'abc' });

		var req = { method: 'POST' };
		var res = session.run(req);
		req.allowCsrf();
		runGuard(res);
	});
	it('should do nothing if token was validated', function () {
		var session = new Session({ key: 'abc' });

		var res1 = session.run({});
		var formToken = res1.getFormToken();

		var req2 = { method: "POST" };
		var res2 = session.run(req2);
		req2.verifyToken(formToken);
		runGuard(res2);
	});
	it('should do nothing if invalid token was validated', function () {
		var session1 = new Session({ key: 'abc' });

		var res1 = session1.run({});
		var formToken = res1.getFormToken();

		var session2 = new Session({ key: 'def' });
		session2.cookies._csrfKey = session1.cookies._csrfKey;

		var req2 = { method: "POST" };
		var res2 = session2.run(req2);
		req2.verifyToken(formToken);
		runGuard(res2);
	});
});