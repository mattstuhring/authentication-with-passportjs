const knex = require('./knex');
const bcrypt = require('bcrypt');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const { ExtractJwt } = require('passport-jwt');


// ************ JSON Web Token Strategy *************
// **************************************************
passport.use(new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromHeader('authorization'), // where the token located
  secretOrKey: process.env.JWT_SECRET
}, (payload, done) => {
  // find the user specified in token
  knex('users')
    .select('user_id', 'user_email')
    .where('user_id', payload.sub)
    .first()
    .then((user) => {
      // if user doesn't exist handle it
      if (!user) {
        return done(null, false);
      }

      // otherwise return the user
      done(null, user);
    })
    .catch((err) => {
      done(err, false);
    });
}));


// ***************** Local Strategy *****************
// **************************************************
// Passport default uses username and password
// We are going to use email & password
passport.use(new LocalStrategy({
  usernameField: 'email'
}, (email, password, done) => {
  // find user by email
  let user;
  knex('users')
    .select('*')
    .where('user_email', email)
    .first()
    .then((exist) => {
      // if user doesn't exist handle it
      if (!exist) {
        return done(null, false);
      } else {
        user = exist;
      }

      // check user's password
      return bcrypt.compare(password, exist.user_hashed_password);
    })
    .then((isMatch) => {
      // if password doesn't match handle it
      if (!isMatch) {
        return done(null, false);
      }

      // otherwise return the user
      done(null, user);
    })
    .catch((err) => {
      done(err, false);
    });
}));
