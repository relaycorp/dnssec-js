const mainJestConfig = require('../../jest.config.mjs');

module.exports = {
  preset: mainJestConfig.preset,
  roots: ['.'],
  testEnvironment: mainJestConfig.testEnvironment,
  setupFilesAfterEnv: mainJestConfig.setupFilesAfterEnv
};
