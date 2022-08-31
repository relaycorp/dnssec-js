const mainJestConfig = require('../../jest.config.cjs');

module.exports = {
  preset: mainJestConfig.preset,
  roots: ['.'],
  testEnvironment: mainJestConfig.testEnvironment,
  setupFilesAfterEnv: mainJestConfig.setupFilesAfterEnv
};
