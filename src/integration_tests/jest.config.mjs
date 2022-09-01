const mainJestConfig = require('../../jest.config.mjs');

export default {
  preset: mainJestConfig.preset,
  roots: ['.'],
  testEnvironment: mainJestConfig.testEnvironment,
  setupFilesAfterEnv: mainJestConfig.setupFilesAfterEnv,
};
