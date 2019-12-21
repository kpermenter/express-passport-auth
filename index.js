const express = require("express");
const app = express();
const models = require('./models');
const bodyParser = require("body-parser");

var pbkdf2 = require('pbkdf2');
var crypto = require('crypto');
var salt = crypto.randomBytes(20).toString('hex');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.post("/sign-up", function (req, response) {
  console.log('creating User');
  console.log(req.body);

  var key = pbkdf2.pbkdf2Sync(
    req.body.password, salt, 36000, 256, 'sha256'
  );
  var hash = key.toString('hex');

  models.user.create({ username: req.body.username, password: `pbkdf2_sha256$36000$${salt}$${hash}` })
    .then(function (user) {
      response.send(user);
    });
});

app.post("/login", function (req, response) {
  console.log("login");

  models.user.findOne({where: {username: req.body.username}}).then(function (user) {
    var pass_parts = user.password.split('$');
    var key = pbkdf2.pbkdf2Sync(
      req.body.password,
      pass_parts[2],
      parseInt(pass_parts[1]),
      256, 'sha256'
    );
    var hash = key.toString('hex');
    if (hash === pass_parts[3]) {
      response.send('Passwords Matched!');
    }
  });
})

app.listen(3000, function () {
  console.log('server listening on port 3000');
})