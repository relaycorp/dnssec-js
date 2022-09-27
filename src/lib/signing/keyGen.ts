import { generateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';

import { DnssecAlgorithm } from '../DnssecAlgorithm';

export const generateKeyPairAsync = promisify(generateKeyPair);

interface KeyGenOptions {
  readonly type: string;
  readonly options?: object;
}

const RSA_MODULUS = 2048;
const RSA_PSS_TYPE = 'rsa-pss';
const KEY_GEN_OPTIONS: { readonly [key in DnssecAlgorithm]: KeyGenOptions } = {
  [DnssecAlgorithm.DSA]: { type: 'dsa' },
  [DnssecAlgorithm.ECDSAP256SHA256]: { type: 'ec', options: { namedCurve: 'prime256v1' } },
  [DnssecAlgorithm.ECDSAP384SHA384]: { type: 'ec', options: { namedCurve: 'secp384r1' } },
  [DnssecAlgorithm.RSASHA1]: {
    type: RSA_PSS_TYPE,
    options: {
      modulusLength: RSA_MODULUS,
      hashAlgorithm: 'sha1',
      mgf1HashAlgorithm: 'sha1',
    },
  },
  [DnssecAlgorithm.RSASHA256]: {
    type: RSA_PSS_TYPE,
    options: {
      modulusLength: RSA_MODULUS,
      hashAlgorithm: 'sha256',
      mgf1HashAlgorithm: 'sha256',
    },
  },
  [DnssecAlgorithm.RSASHA512]: {
    type: RSA_PSS_TYPE,
    options: {
      modulusLength: RSA_MODULUS,
      hashAlgorithm: 'sha512',
      mgf1HashAlgorithm: 'sha512',
    },
  },
  [DnssecAlgorithm.ED25519]: { type: 'ed25519' },
  [DnssecAlgorithm.ED448]: { type: 'ed448' },
};

export function getKeyGenOptions(dnssecAlgorithm: DnssecAlgorithm): KeyGenOptions {
  const algorithm = KEY_GEN_OPTIONS[dnssecAlgorithm];
  if (!algorithm) {
    throw new Error(`Unsupported algorithm (${dnssecAlgorithm})`);
  }
  return algorithm;
}
