import { generateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';

import { DNSSECAlgorithm } from '../DNSSECAlgorithm';

export const generateKeyPairAsync = promisify(generateKeyPair);

interface KeyGenOptions {
  readonly type: string;
  readonly options: object;
}

const RSA_MODULUS = 2048;
const RSA_PSS_TYPE = 'rsa-pss';
const KEY_GEN_OPTIONS: { readonly [key in DNSSECAlgorithm]: KeyGenOptions } = {
  [DNSSECAlgorithm.DSA]: { type: 'dsa', options: {} },
  [DNSSECAlgorithm.RSASHA1]: {
    type: RSA_PSS_TYPE,
    options: {
      modulusLength: RSA_MODULUS,
      hashAlgorithm: 'sha1',
      mgf1HashAlgorithm: 'sha1',
    },
  },
  [DNSSECAlgorithm.RSASHA256]: {
    type: RSA_PSS_TYPE,
    options: {
      modulusLength: RSA_MODULUS,
      hashAlgorithm: 'sha256',
      mgf1HashAlgorithm: 'sha256',
    },
  },
};

export function getKeyGenOptions(dnssecAlgorithm: DNSSECAlgorithm): KeyGenOptions {
  const algorithm = KEY_GEN_OPTIONS[dnssecAlgorithm];
  if (!algorithm) {
    throw new Error(`Unsupported algorithm (${dnssecAlgorithm})`);
  }
  return algorithm;
}
