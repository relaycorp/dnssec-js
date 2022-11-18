import { generateKeyPair as cryptoGenerateKeyPair, KeyObject } from 'node:crypto';
import { promisify } from 'node:util';

import { DnssecAlgorithm } from '../DnssecAlgorithm';

export const generateKeyPairAsync = promisify(cryptoGenerateKeyPair);

interface KeyGenOptions {
  readonly type: string;
  readonly options?: object;
}

const RSA_OPTIONS = {
  type: 'rsa',
  options: { modulusLength: 2048 },
};
const KEY_GEN_OPTIONS: { readonly [key in DnssecAlgorithm]: KeyGenOptions } = {
  [DnssecAlgorithm.DSA]: { type: 'dsa' },
  [DnssecAlgorithm.ECDSAP256SHA256]: { type: 'ec', options: { namedCurve: 'prime256v1' } },
  [DnssecAlgorithm.ECDSAP384SHA384]: { type: 'ec', options: { namedCurve: 'secp384r1' } },
  [DnssecAlgorithm.RSASHA1]: RSA_OPTIONS,
  [DnssecAlgorithm.RSASHA256]: RSA_OPTIONS,
  [DnssecAlgorithm.RSASHA512]: RSA_OPTIONS,
  [DnssecAlgorithm.ED25519]: { type: 'ed25519' },
  [DnssecAlgorithm.ED448]: { type: 'ed448' },
};

export interface KeyPair {
  // No, Node.js' typings don't offer this interface as of this writing.
  readonly publicKey: KeyObject;
  readonly privateKey: KeyObject;
}

export async function generateKeyPair(algorithm: DnssecAlgorithm): Promise<KeyPair> {
  const options = KEY_GEN_OPTIONS[algorithm];
  if (!options) {
    throw new Error(`Unsupported algorithm (${algorithm})`);
  }
  return generateKeyPairAsync(options.type as any, options.options);
}
