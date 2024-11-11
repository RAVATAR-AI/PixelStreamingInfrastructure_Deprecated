const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const db = require('../db');

module.exports = new LocalStrategy((username, password, callback) => {
  db.users.findByUsername(username, (err, user) => {
    if (err) {
      console.log(`Unable to login '${username}', error ${err}`);
      return callback(err);
    }

    // User not found
    if (!user) {
      console.log(`User '${username}' not found`);
      return callback(null, false);
    }

    // Compare hashed passwords
    bcrypt.compare(password, user.passwordHash, (err, isValid) => {
      if (err) {
        console.log(`Error comparing password for user '${username}': ${err}`);
        return callback(err);
      }
      
      if (!isValid) {
        console.log(`Password incorrect for user '${username}'`);
        return callback(null, false);
      }

      console.log(`User '${username}' logged in`);
      return callback(null, user);
    });
  });
});
