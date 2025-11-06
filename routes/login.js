var log4js = require("log4js");
var url = require("url");
var express = require('express');
var auth = require("../model/auth");
var router = express.Router();

var logger = log4js.getLogger('vnode')

// Login template
router.get('/login', function(req, res, next) {

    var url_params = url.parse(req.url, true).query;

    res.render('login', {returnurl: url_params.returnurl, auth_error: url_params.error});
});


// Do auth
router.post('/login/auth', function(req, res) {

    var user = req.body.username;
    var password = req.body.password;
    var returnurl = req.body.returnurl;

    // Only allow relative paths starting with '/' (not double slashes, no http(s))
    function isSafeRelativeUrl(u) {
        return typeof u === 'string' && u.startsWith("/") && !u.startsWith("//") && !/^\/{2,}/.test(u) && !u.includes("://");
    }

    logger.error("Tried to login attempt from user = " + user);

    auth(user, password)
        .then(function (data) {
            req.session.logged = true;
            req.session.user_name = user;

            if (!isSafeRelativeUrl(returnurl)) {
                returnurl = "/";
            }

            res.redirect(returnurl);
        })
        .catch(function (err) {
            // Sanitize returnurl also in error path
            if (!isSafeRelativeUrl(returnurl)) {
                returnurl = "/";
            }
            res.redirect("/login?returnurl=" + encodeURIComponent(returnurl) + "&error=" + encodeURIComponent(err.message));
        });

});

// Do logout
router.get('/logout', function(req, res, next) {

    req.session.logged = false;
    req.session.user = null;

    res.redirect("/login")
});

module.exports = router;
