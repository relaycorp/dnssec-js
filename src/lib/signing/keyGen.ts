import { generateKeyPair, RSAPSSKeyPairKeyObjectOptions } from 'node:crypto';
import { promisify } from 'node:util';

import { DNSSECAlgorithm } from '../DNSSECAlgorithm';

export const generateKeyPairAsync = promisify(generateKeyPair);

interface KeyGenOptions {
  readonly type: string;
  readonly options: object;
}

export function getKeyGenOptions(dnssecAlgorithm: DNSSECAlgorithm): KeyGenOptions {
  // TODO: Support more algorithms
  switch (dnssecAlgorithm) {
    case DNSSECAlgorithm.RSASHA256:
      const options: RSAPSSKeyPairKeyObjectOptions = {
        modulusLength: 2048,
        hashAlgorithm: 'sha256',
        mgf1HashAlgorithm: 'sha256',
      };
      return { type: 'rsa-pss', options };
  }
}
