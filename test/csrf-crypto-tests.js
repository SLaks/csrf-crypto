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

	req.connection = req.connection || {};
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

		var res = session.run({ user: "2|SLaks" });
		var formToken = res.getFormToken();

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

		var res = session.run({ connection: { encrypted: true } });
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