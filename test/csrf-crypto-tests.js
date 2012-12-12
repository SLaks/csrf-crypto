/*jshint node: true, camelcase: true, eqeqeq: true, forin: true, immed: true, latedef: true, newcap: true, noarg: true, undef: true, globalstrict: true*/
/*global describe:false, it:false */
"use strict";

var mocha = require("mocha");
var assert = require("assert");

var csrfCrypto = require('..');


//TODO: Test userData() with "|"

function Session(csrfOptions) {
	this.middleware = csrfCrypto(csrfOptions);
	this.cookies = {};
}
Session.prototype.run = function (req) {
	//Mock as much of the response object as I need

	req.cookies = this.cookies;

	var res = req.res = req.res || {};
	res.req = req;
	res.cookies = res.cookies || {};
	res.cookie = res.cookie || function (name, value, options) {
		this.cookies[name] = value;
		req.cookies[name] = value;
	};
	res.clearCookie = function (name, options) {
		delete req.cookies[name];
	};

	this.middleware(req, res, function () { });

	return res;
};

describe('#csrfCrypto', function () {
	it('should succeed under normal circumstances', function (done) {
		var session = new Session({ key: 'abc' });

		var res = session.run({});
		var formToken = res.getFormToken();

		var req2 = {};
		session.run(req2);
		assert.ok(req2.verifyToken(formToken));
		done();
	});
});