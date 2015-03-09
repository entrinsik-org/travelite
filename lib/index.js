'use strict';

var passport = require('passport');
var hapi = null;
var internals = {};

/**
 * Passport adapter for Hapi. Based on Travelogue, but changed to remove all reference to sessions/yar/cookies.
 *
 * @param server
 * @param options
 * @param next
 */
exports.register = function (server, options, next) {
    internals.setHapi(server.hapi);
    server.expose('passport', passport);
    passport.framework({
        initialize: internals.initialize,
        authenticate: internals.authenticate()
    });
    var mw = passport.initialize();
    server.ext('onPreAuth', function(req, reply) {
        mw(req, function (err) {
            if (err) return reply(err);

            reply.continue();
        });
    });
    server.auth.scheme('passport', internals.implementation);
    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};

internals.initialize = function (passport) {
    return function (request, next) {
        request._passport = {};
        request._passport.instance = passport;
        next();
    };
};

internals.authenticate = function () {
    return function (passport, name, options, callback) {
        if (!callback &&
            typeof options === 'function') {

            callback = options;
            options = {};
        }
        options = options || {};
        if (!Array.isArray(name)) {
            name = [name];
        }
        return function authenticate(request, reply, next) {
            var failures = [];
            if (!next) {
                next = function (err) {
                    if (err && err.isBoom) {
                        return reply(err);
                    } else {
                        return err ? reply(hapi.error.unauthorized('Unauthorized')) : reply(request.user);
                    }
                };
            }
            var allFailed = internals.allFailedFactory(request, reply, failures, options, callback);
            var attempt = internals.attemptFactory(passport, request, reply, name, failures, allFailed, options, next, callback);
            attempt(0, next);
        };
    };
};

internals.getChallenges = function (failures) {
    var rchallenge = [];
    var rstatus = null;
    for (var i = 0, l = failures.length; i < l; ++i) {
        var failure = failures[i];
        var challenge = failure.challenge || {};
        var status = failure.status;
        if (typeof challenge === 'number') {
            status = challenge;
            challenge = null;
        }
        rstatus = rstatus || status;
        if (typeof challenge === 'string') {
            rchallenge.push(challenge);
        }
    }
    return rchallenge;
};


internals.allFailedFactory = function (request, reply, failures, options, callback) {
    return function allFailed() {
        if (callback) {
            if (failures.length === 1) {
                return callback(null, false, failures[0].challenge, failures[0].status);
            }
            else {
                var challenges = failures.map(function (f) {
                    return f.challenge;
                });
                var statuses = failures.map(function (f) {
                    return f.status;
                });
                return callback(null, false, challenges, statuses);
            }
        }
        return reply(hapi.error.unauthorized('Unauthorized', internals.getChallenges(failures) || null));
    };
};


internals.attemptFactory = function (passport, request, reply, name, failures, allFailed, options, next, callback) {
    return function attempt(i, cb) {
        var delegate = {};
        delegate.success = function (user, info) {
            if (callback) {
                return callback(null, user, info);
            }
        };
        delegate.fail = function (challenge, status) {
            failures.push({
                challenge: challenge,
                status: status
            });
            return attempt(i + 1, cb);
        };
        delegate.error = internals.delegateErrorFactory(cb);
        var layer = name[i];
        if (!layer) {
            return allFailed();
        }
        var prototype = passport._strategy(layer);
        if (!prototype) {
            return next(hapi.error.internal('No strategy registered under the name:' + layer));
        }
        var actions = internals.actionsFactory();
        var strategy = Object.create(prototype);

        for (var method in actions) {
            if (actions.hasOwnProperty(method)) {
                strategy[method] = actions[method].bind(delegate);
            }
        }

        // Synthetic Request passed to Strategy (avoid polluting request)
        var req = {};
        req.headers = request.headers;
        req.query = request.url.query;
        req.body = request.payload;
        req._passport = request._passport;
        request._synth = req;
        // Accommodate passport-google in Sythentic Request
        req.url = request.url;
        req.url.method = request.method.toUpperCase();
        req.url.url = request.url.href;
        // Perform Authentication with Synthetic Request
        strategy.authenticate(req, options);
    };
};

internals.actionsFactory = function () {
    return {
        success: function () {
            this.success.apply(this, arguments);
        },
        fail: function () {
            this.fail.apply(this, arguments);
        },
        redirect: function () {
            this.redirect.apply(this, arguments);
        },
        error: function () {
            this.error.apply(this, arguments);
        }
    };
};

internals.delegateErrorFactory = function (cb) {
    return function (err) {
        if (err) {
            err = hapi.error.internal('Passport Error: ' + err);
        }
        return cb(err);
    };
};

internals.implementation = function () {
    return function () {
        var scheme = {
            authenticate: function (request, reply) {
                if (request.header.authorization) {
                    return reply(null, { credentials: request.user });
                }
                return reply(new hapi.error.unauthorized('Unauthorized'));
            }
        };
        return scheme;
    };
};

internals.setHapi = function (module) {
    hapi = hapi || module;
};
