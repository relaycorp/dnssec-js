import { generateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';

import { DNSSECAlgorithm } from '../DNSSECAlgorithm';

export const generateKeyPairAsync = promisify(generateKeyPair);

interface KeyGenOptions {
  readonly type: string;
  readonly options?: object;
}

const RSA_MODULUS = 2048;
const RSA_PSS_TYPE = 'rsa-pss';
const KEY_GEN_OPTIONS: { readonly [key in DNSSECAlgorithm]: KeyGenOptions } = {
  [DNSSECAlgorithm.DSA]: { type: 'dsa' },
  [DNSSECAlgorithm.ECDSAP256SHA256]: { type: 'ec', options: { namedCurve: 'prime256v1' } },
  [DNSSECAlgorithm.ECDSAP384SHA384]: { type: 'ec', options: { namedCurve: 'secp384r1' } },
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
  [DNSSECAlgorithm.RSASHA512]: {
    type: RSA_PSS_TYPE,
    options: {
      modulusLength: RSA_MODULUS,
      hashAlgorithm: 'sha512',
      mgf1HashAlgorithm: 'sha512',
    },
  },
  [DNSSECAlgorithm.ED25519]: { type: 'ed25519' },
  [DNSSECAlgorithm.ED448]: { type: 'ed448' },
};

export function getKeyGenOptions(dnssecAlgorithm: DNSSECAlgorithm): KeyGenOptions {
  const algorithm = KEY_GEN_OPTIONS[dnssecAlgorithm];
  if (!algorithm) {
    throw new Error(`Unsupported algorithm (${dnssecAlgorithm})`);
  }
  return algorithm;
}
