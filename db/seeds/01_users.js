'use strict';

exports.seed = function(knex) {
  return knex('users').del()
    .then(function() {
      return knex('users').insert([
        {
          user_id: 1,
          user_email: 'test@test.com',
          user_hashed_password: '$2a$10$e9wOPCUIDk3LT9xw.Heii.zvP9PhV0CkES.kllKLw6x7rlkNAU7Da',
          created_at: new Date('2019-02-15 12:00:00'),
          updated_at: new Date('2019-02-15 12:00:00')
        }
      ]);
    })
    .then(function() {
      return knex.raw(
        "SELECT setval('users_user_id_seq', (SELECT MAX(user_id) FROM users));"
      )
    });
};
