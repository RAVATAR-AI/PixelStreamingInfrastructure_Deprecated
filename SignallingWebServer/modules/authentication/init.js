// Copyright Epic Games, Inc. All Rights Reserved.
// Adapted from 
// * https://blog.risingstack.com/node-hero-node-js-authentication-passport-js/
// * https://github.com/RisingStack/nodehero-authentication/tree/master/app
// * https://github.com/passport/express-4.x-local-example


const passport = require('passport');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const localStrategy = require('./strategies/localStrategy');
const checkActiveInstanceStrategy = require('./strategies/checkActiveInstanceStrategy');
const path = require('path');
const fs = require('fs');
var db = require('./db');

function initPassport (app, config) {
	config = config || {};

	// Generate session secret if it doesn't already exist and save it to file for use next time
	let authConfig = {};
	let configPath = path.join(__dirname, './config.json');

	if (fs.existsSync(configPath)) {
		let content = fs.readFileSync(configPath, 'utf8');
		try {
			authConfig = JSON.parse(content);
		} catch (e) {
			console.log(`Error with config file '${configPath}': ${e}`);
		}
	}

	if (!authConfig.sessionSecret) {
		authConfig.sessionSecret = bcrypt.genSaltSync(12);
		let content = JSON.stringify(authConfig);
		fs.writeFileSync(configPath, content);
	}

	// Setup session id settings
	app.use(session({
		secret: authConfig.sessionSecret,
		resave: false,
		saveUninitialized: false,
		cookie: {
			secure: true,
			sameSite: 'none',
			maxAge: 24 * 60 * 60 * 1000 /* 1 day */
			//maxAge: 5 * 1000 /* 5 seconds */
		}
	}));
	
	app.use(passport.initialize());
	app.use(passport.session());
	
	passport.serializeUser(function(user, cb) {
	 	cb(null, user.id);
	});

	passport.deserializeUser(function(id, cb) {
	 	db.users.findById(id, function (err, user) {
			if (err) { return cb(err); }
			cb(null, user);
		});
	});

	console.log('Setting up auth');

	if (config.ApiDomain) {
		console.log('Using custom auth strategy');
		passport.use('custom', checkActiveInstanceStrategy(config));
	} else {
		console.log('Using local auth strategy');
		passport.use(localStrategy);
	}
	
	
	passport.authenticationMiddleware = function authenticationMiddleware(redirectUrl) {
		return function(req, res, next) {
			if (req.isAuthenticated()) {
				return next();
			}
			console.log("authenticate");
			req.session.redirectTo = req.originalUrl;
			return passport.authenticate('custom', { failureRedirect: redirectUrl })(req, res, next);
		}
	}
}

module.exports = initPassport;
