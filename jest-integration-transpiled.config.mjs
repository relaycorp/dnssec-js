import mainJestConfig from './jest.config.mjs';

const CONFIG = {
  ...mainJestConfig,
  moduleFileExtensions: ['js'],
  preset: null,
  roots: ['build/lib/integration_tests']
};

export default CONFIG;
