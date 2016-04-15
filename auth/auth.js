var jwt = require('jwt-simple');
var User = require('../models/user');
var config = require('../config/config');
var bcrypt = require('bcrypt');

var auth = {

  login: function(req, res) {

    var username = req.body.username || '';
    var password = req.body.password || '';
    console.log('u: ' + username);
    console.log('p: ' + password);

    if (username == '' || password == '') {
      res.status(401);
      res.json({
        "status": 401,
        "message": "Invalid credentials"
      });
      return;
    }

    auth.getUser(username, function(dbUserObj,err) {
      if (!dbUserObj) {
        res.status(401);
        res.json({
          "status": 401,
          "message": "Invalid credentials"
        });
        return;
      }

      if (dbUserObj) {


        bcrypt.compare(password,dbUserObj.password, function(err, passmatch) {
            if (passmatch == true) {
              res.json(genToken(dbUserObj));
            } else {
              res.status(401);
              res.json({
                "status": 401,
                "message": "Invalid credentials"
              });
              return;
            }
        });
      }
    });

  },

  getUser: function(username,callback) {
      User.findOne({ username: username }, function (err,user) {
        if (err) {
          console.log(err);
          callback(false);
        } else {
          callback(user);
        }
      });
  },

  isUserAdmin: function(username,callback) {
      User.findOne({ username: username }, function (err,user) {
        if (user.role == 'admin') {
          callback(true);
        } else {
          callback(false);
        }
      });
  },
  encryptPass: function(password,callback) {
      bcrypt.hash(password, 12, function(err, hash) {
        if (hash) {
          callback(hash);
        } else {
          console.log(err);
        }
      });
  }
}

/** private methods **/

function genToken(user) {
  var expires = expiresIn(1); // 7 days
  var token = jwt.encode({
    exp: expires
  }, config.jwtsecret);

  return {
    token: token,
    expires: expires,
    user: user.username
  };
}

function expiresIn(numDays) {
  var dateObj = new Date();
  return dateObj.setDate(dateObj.getDate() + numDays);
}

module.exports = auth;
