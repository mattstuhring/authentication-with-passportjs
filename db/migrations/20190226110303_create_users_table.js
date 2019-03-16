'use strict';

exports.up = function(knex, Promise) {
  return knex.schema.createTable('users', (table) => {
    table.increments('user_id');
    table.string('user_email').unique().notNullable().defaultTo('');
    table.specificType('user_hashed_password', 'char(60)').notNullable();
    table.timestamps(true, true);
  })
};

exports.down = function(knex, Promise) {
  return knex.schema.dropTable('users');
};
