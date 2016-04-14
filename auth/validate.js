var jwt = require('jwt-simple');
var getUser = require('./auth').getUser;
var config = require('../config/config');


module.exports = function(req, res, next) {

  var token = req.headers['x-access-token'];
  var key = req.headers['x-key'];

  if (token || key) {
    try {
      var decoded = jwt.decode(token, config.jwtsecret);

      if (decoded.exp <= Date.now()) {
        res.status(400);
        res.json({
          "status": 400,
          "message": "Token Expired"
        });
        return;
      }

      // Authorize the user for access
      getUser(key ,function (dbUser,err) {
          if (dbUser) {
              next(); // user exists, move on
          } else {
            res.status(401);
            res.json({
              "status": 401,
              "message": "Invalid User"
            });
            return;
          }
      }); 

    } catch (err) {
      res.status(500);
      res.json({
        "status": 500,
        "message": "Token Error."
      });
    }
  } else {
      res.status(401);
      res.json({
        "status": 401,
        "message": "Invalid Token or Key"
      });
    return;
  }
};
