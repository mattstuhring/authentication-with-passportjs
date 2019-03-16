const express = require('express');
const router = express.Router();
const knex = require('../knex');
const humps = require('humps');
const bcrypt = require('bcrypt');
const JWT = require('jsonwebtoken');
const passport = require('passport');
const passportConfig = require('../passport');
const { validateBody, schemas } = require('../helpers/routeHelpers');

// sign a token with 1 day expiration
const signToken = (userId) => {
  return JWT.sign(
    {
      iss: 'fusedglass',
      sub: userId,
      iat: new Date().getTime(), // current time
      exp: new Date().setDate(new Date().getDate() + 1) // current time + 1 day ahead
    },
    process.env.JWT_SECRET
  );
};

// *****************  SIGNUP  ****************
// *******************************************
router.post('/signup', validateBody(schemas.authSchema), (req, res, next) => {
  // req.value from Joi validation
  const email = req.value.body.email;
  const password = req.value.body.password;

  // check if the user already exists in db
  knex('users')
    .select('user_email')
    .where('user_email', email)
    .first()
    .then((row) => {
      if (row) {
        let err = new Error('Email already exists!');
        err.statusCode = 403;
        throw err;
      }

      // generate a password hash (salt + hash)
      const saltRounds = 12;
      return bcrypt.hash(password, saltRounds);
    })
    .then((hashedPassword) => {
      // create a new user
      let newUser = {
        userEmail: email,
        userHashedPassword: hashedPassword
      };

      newUser = humps.decamelizeKeys(newUser);

      // insert user into db & return user's ID
      return knex('users').returning('user_id').insert(newUser);
    })
    .then((userId) => {
      // generate the token
      const token = signToken(userId[0]);

      // respond with token
      res.status(200).send({ token });
    })
    .catch((err) => {
      next(err);
    });
});





// *****************  SIGNIN  ****************
// *******************************************
router.post('/signin', validateBody(schemas.authSchema), passport.authenticate('local', { session: false }), (req, res, next) => {

  // console.log('req.user', req.user);
  const token = signToken(req.user);

  console.log('Successful login!');

});




router.get('/secret', passport.authenticate('jwt', { session: false }), (req, res, next) => {
  console.log('I managed to get here');
  res.send({ secret: 'resources' })
});


module.exports = router;
