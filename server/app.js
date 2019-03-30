require('dotenv').config();

const express = require('express');
const morgan = require('morgan');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(morgan('dev'));
app.use(bodyParser.json());

// Routes
app.use('/users', require('./routes/users'));

// 404 catch all
app.use((_req, res, _next) => {
  res.sendStatus(404);
});

// Error handling
app.use((err, req, res, next) => {
  // If no specified error code, set to 'Internal Server Error (500)'
  if (!err.statusCode) {
    err.statusCode = 500;
  }
  // Send error with status code and message
  res.status(err.statusCode).send(err.message);
});

// Start server
app.listen(PORT, () => {
  console.log(`App listening on PORT ${PORT}`);
});
