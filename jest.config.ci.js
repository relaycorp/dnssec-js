const mainJestConfig = require('./jest.config');

module.exports = Object.assign({}, mainJestConfig, {
  collectCoverageFrom: ["build/main/lib/**/*.js"],
  moduleFileExtensions: ['js'],
  preset: null,
  roots: ['build/main/lib']
});
