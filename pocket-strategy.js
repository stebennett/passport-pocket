var needle = require('needle'),
    passport = require('passport'),
    util = require('util');

function OAuth(options){
    this.options = options;
    this.authUrl = "https://getpocket.com/auth/authorize?request_token={:requestToken}&redirect_uri={:redirectUri}"

    this.requestOptions = {
        json: true,
        headers: {
            'x-accept': 'application/json',
            'accept': '*/*',
            'content-type': 'application/json'
        }
    }

    return this;
}

OAuth.prototype._formatAuthUrl = function(token, redirectUri) {
    return this.authUrl.replace('{:requestToken}', token)
     .replace('{:redirectUri}', redirectUri);
};

OAuth.prototype.getOAuthAccessToken = function (code, callback) {
    var oauth = this;

    needle.post(
        oauth.options.authorizationURL,
        {
            consumer_key : oauth.options.consumerKey,
            code         : code
        },
        oauth.requestOptions,
        function(error, response) {
            if(error) { return callback(error, null)}
            if(response.statusCode === 400) { return callback(400, null)}
            if(response.statusCode === 403) { return callback(403, null)}

            callback(null, response.body.username, response.body.access_token);
        }
    );
}

OAuth.prototype.getOAuthRequestToken = function (callback) {
    var oauth = this;

    needle.post(
        oauth.options.requestTokenURL,
        {
            consumer_key: oauth.options.consumerKey,
            redirect_uri: oauth.options.callbackURL
        },
        oauth.requestOptions,
        function (error, response) {
            if(error) { return callback(error, null)}
            if(response.statusCode === 400) {return callback(400, null)}

            var url  = oauth._formatAuthUrl(response.body.code, oauth.options.callbackURL);

            callback(null, response.body.code, url);
        }
    );
}

function Strategy(options, verify) {
    options = options || {};
    options.requestTokenURL  = options.requestTokenURL || 'https://getpocket.com/v3/oauth/request';
    options.authorizationURL = options.userAuthorizationURL || 'https://getpocket.com/v3/oauth/authorize';
    options.sessionKey       = options.sessionKey || 'oauth:pocket';

    // Api urls
    options.retrive = 'https://getpocket.com/v3/get';

    this._options = options;
    this._verity          = verify;
    this._oauth = new OAuth(options);

    this.name = 'pocket';
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req, options) {
    if (req.query && req.query.denied) {
        return this.fail();
    }

    options = options || {};
    if (!req.session) { return this.error(new Error('OAuth authentication requires session support')); }

    var self = this;

    if (req.session && req.session.pocketCode) {
        function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            req.session.pocketData.info = info;

            self.success(user, info);
        }

        if(req.session.pocketData){
            self.pass(req.session.pocketData.username, req.session.pocketData.info);
        }else{        
            this._oauth.getOAuthAccessToken(req.session.pocketCode, function (err, username, accessToken) {
                if(err || !username) { self.error(err); return}
                req.session.pocketData = {
                    username : username,
                    accessToken : accessToken
                }

                self._verity(username, accessToken, verified);
            });
        }
    }else{
        this._oauth.getOAuthRequestToken(function (err, code, authUrl) {
            if(err) { self.error(err)}

            req.session.pocketCode = code;

            self.redirect(authUrl);
        });
    }
}

Strategy.prototype.getUnreadItems = function(accessToken, callback) {
    var strategy = this;
    needle.post(
        strategy._options.retrive,
        {
            consumer_key : strategy._options.consumerKey,
            access_token : accessToken,
            state        : 'unread'
        },
        strategy.requestOptions,
        function (error, response) {
            callback(error, response.body)
        }
    );
};

module.exports = Strategy;
