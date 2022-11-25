import { dirname } from 'node:path';

import mainJestConfig from '../../jest.config.mjs';

const currentFilePath = new URL(import.meta.url).pathname;
const currentDirectoryPath = dirname(currentFilePath);

const CONFIG = {
  ...mainJestConfig,
  roots: [currentDirectoryPath],
};

export default CONFIG;
