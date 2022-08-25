const mainJestConfig = require('../../jest.config');

module.exports = {
  preset: mainJestConfig.preset,
  roots: ['.'],
  testEnvironment: mainJestConfig.testEnvironment,
  setupFilesAfterEnv: mainJestConfig.setupFilesAfterEnv
};
