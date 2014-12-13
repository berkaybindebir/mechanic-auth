/**
 *
 * Created by uur on 14/07/14.
 */

// Load modules
var Boom = require("boom");
var Hoek = require("hoek");

var internals = {};

exports.register = function (server, options, next) {

    // Inserting authenticated user into view context
    server.ext("onPreResponse", function (request, reply) {
        var response = request.response;
        // if response type view!
        if (request.auth && request.auth.isAuthenticated && response.variety && response.variety === "view") {
            response.source.context = response.source.context || {};
            response.source.context.credentials = request.auth.credentials;
        }
        return reply.continue();
    });

    server.auth.scheme("token", internals.tokenImplementation);
    server.auth.scheme("cookie", internals.cookieImplementation);

    next();
};

internals.tokenImplementation = function (server, options) {
    Hoek.assert(options, "Missing token auth strategy options");
    Hoek.assert(!options.validateFunc || typeof options.validateFunc === "function", "Invalid validateFunc method in configuration");

    return {
        authenticate: function (request, reply) {

            // Get role & policies
            var roles = request.route.plugins["mechanic-auth"] || [];

            var req = request.raw.req;
            var authorization = req.headers.authorization;

            if (!authorization) {
                return reply(Boom.unauthorized(null, "Mechanic-Auth"));
            }

            var parts = authorization.split(/\s+/);

            if (parts.length !== 2) {
                return reply(Boom.badRequest("Mechanic-Auth"));
            }

            if (parts[0] && parts[0].toLowerCase() !== "bearer") {
                return reply(Boom.unauthorized(null, "Mechanic-Auth"));
            }

            var validate = function (secret, token) {
                return function (err, credentials) {
                    if (err) {
                        return reply(err);
                    }

                    if (!credentials || (secret && (!credentials.secret || credentials.secret !== secret))) {
                        return reply(Boom.unauthorized("Invalid token or permissions", "Bearer"), {credentials: credentials});
                    }

                    return reply(null, {credentials: credentials});
                }
            };

            var tokenParts = new Buffer(parts[1] || "", "base64").toString("utf8").split(":");
            if (tokenParts.length !== 2) {
                return reply(Boom.badRequest("Bad HTTP authentication token value format"));
            }

            return options.validateFunc(tokenParts[0], tokenParts[1], roles, validate(tokenParts[0], tokenParts[1]));
        }
    };
};

internals.cookieImplementation = function (server, options) {

    Hoek.assert(options, "Missing cookie auth strategy options");
    Hoek.assert(!options.validateFunc || typeof options.validateFunc === "function", "Invalid validateFunc method in configuration");
    Hoek.assert(options.password, "Missing required password in configuration");

    var settings = Hoek.clone(options);                        // Options can be reused
    settings.cookie = settings.cookie || "sid";

    var cookieOptions = {
        encoding: "iron",
        password: settings.password,
        path: "/",
        isHttpOnly: true,
        clearInvalid: true,
        isSecure: false
    };

    if (settings.domain) {
        cookieOptions.domain = settings.domain;
    }

    if (settings.path) {
        cookieOptions.path = settings.path;
    }

    if (typeof settings.appendNext === "boolean") {
        settings.appendNext = (settings.appendNext ? "next" : "");
    }

    server.state(settings.cookie, cookieOptions);

    server.ext("onPreAuth", function (request, reply) {

        request.auth.session = request.auth.session || {};
        request.auth.session[settings.cookie] = request.auth.session[settings.cookie] || {};

        request.auth.session[settings.cookie] = {
            set: function (session, ttl) {
                Hoek.assert(session && typeof session === "object", "Invalid session");
                request.auth.artifacts = session;

                if (ttl) {
                    reply.state(settings.cookie, session, {ttl: 30 * 24 * 60 * 60 * 1000});
                }
                else {
                    reply.state(settings.cookie, session);
                }
            },
            clear: function () {
                request.auth.artifacts = null;
                reply.unstate(settings.cookie);
            }
        };

        return reply.continue();
    });

    var scheme = {
        authenticate: function (request, reply) {

            // Get role & policies
            console.log(request.route);

            var roles = request.route.plugins["mechanic-auth"] || [];

            var validate = function () {

                // Check cookie
                var session = request.state[settings.cookie];

                if (!session) {
                    return unauthenticated(Boom.unauthorized(null, "cookie"));
                }

                settings.validateFunc(session, roles, function (err, isValid, credentials) {

                    if (err || !isValid) {

                        reply.unstate(settings.cookie);

                        return unauthenticated(Boom.unauthorized("Invalid cookie"), {
                            credentials: credentials || session,
                            artifacts: session
                        });
                    }

                    // TODO: extend cookie expiration time if ttl exist.
                    // reply.state(settings.cookie, session);

                    return reply(null, {credentials: credentials || session, artifacts: session});
                });
            };

            var unauthenticated = function (err, result) {

                if (request.auth.mode === "optional") {
                    return reply(err, result);
                }

                if (settings.redirectOnTry === false &&             // Defaults to true
                    request.auth.mode === "try") {

                    return reply(err, result);
                }

                var redirectTo = settings.redirectTo;
                if (request.route.plugins["mechanic-auth"] &&
                    request.route.plugins["mechanic-auth"].redirectTo !== undefined) {

                    redirectTo = request.route.plugins["mechanic-auth"].redirectTo;
                }

                if (!redirectTo) {
                    return reply(err, result);
                }

                var uri = redirectTo;
                if (settings.appendNext) {
                    if (uri.indexOf("?") !== -1) {
                        uri += "&";
                    }
                    else {
                        uri += "?";
                    }

                    uri += settings.appendNext + "=" + encodeURIComponent(request.url.path);
                }

                return reply("You are being redirected...", result).redirect(uri);
            };

            validate();
        }
    };

    return scheme;
};

exports.register.attributes = {
    pkg: require("../package.json")
};