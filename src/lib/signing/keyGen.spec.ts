import { KeyObject } from 'node:crypto';

import { generateKeyPair } from './keyGen';
import { DnssecAlgorithm } from '../DnssecAlgorithm';

describe('generateKeyPair', () => {
  test.each([DnssecAlgorithm.RSASHA1, DnssecAlgorithm.RSASHA256, DnssecAlgorithm.RSASHA512])(
    'Algorithm %s',
    async (algo) => {
      const keyPair = await generateKeyPair(algo);

      expect(keyPair.publicKey).toBeInstanceOf(KeyObject);
      expect(keyPair.privateKey).toBeInstanceOf(KeyObject);
    },
  );
});
