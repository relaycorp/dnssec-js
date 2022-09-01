import { dirname } from 'node:path';

import mainJestConfig from '../../jest.config.mjs';

const currentFilePath = new URL(import.meta.url).pathname;
const currentDirPath = dirname(currentFilePath);

export default {
  ...mainJestConfig,
  roots: [currentDirPath],
};
