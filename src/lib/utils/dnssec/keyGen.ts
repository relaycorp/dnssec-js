import type {
  ECKeyPairKeyObjectOptions,
  ED25519KeyPairKeyObjectOptions,
  ED448KeyPairKeyObjectOptions,
  RSAKeyPairKeyObjectOptions,
  KeyObject,
} from 'node:crypto';
import { generateKeyPair as cryptoGenerateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';

import { DnssecAlgorithm } from '../../DnssecAlgorithm.js';

const generateKeyPairAsync = promisify(cryptoGenerateKeyPair);

type NodejsKeyType = 'ec' | 'ed448' | 'ed25519' | 'rsa';

type NodejsKeyGenOptions =
  | ECKeyPairKeyObjectOptions
  | ED448KeyPairKeyObjectOptions
  | ED25519KeyPairKeyObjectOptions
  | RSAKeyPairKeyObjectOptions;

interface KeyGenOptions {
  readonly type: NodejsKeyType;
  readonly options?: NodejsKeyGenOptions;
}

const RSA_OPTIONS = {
  type: 'rsa' as NodejsKeyType,
  options: { modulusLength: 2048 },
};
const KEY_GEN_OPTIONS: { readonly [key in DnssecAlgorithm]: KeyGenOptions } = {
  [DnssecAlgorithm.RSASHA1]: RSA_OPTIONS,
  [DnssecAlgorithm.RSASHA256]: RSA_OPTIONS,
  [DnssecAlgorithm.RSASHA512]: RSA_OPTIONS,
  [DnssecAlgorithm.ECDSAP256SHA256]: { type: 'ec', options: { namedCurve: 'prime256v1' } },
  [DnssecAlgorithm.ECDSAP384SHA384]: { type: 'ec', options: { namedCurve: 'secp384r1' } },
  [DnssecAlgorithm.ED25519]: { type: 'ed25519' },
  [DnssecAlgorithm.ED448]: { type: 'ed448' },
};

/**
 * Key pair.
 *
 * No, Node.js' typings don't offer this interface as of this writing.
 */
interface KeyPair {
  readonly publicKey: KeyObject;
  readonly privateKey: KeyObject;
}

export async function generateKeyPair(algorithm: DnssecAlgorithm): Promise<KeyPair> {
  if (!(algorithm in KEY_GEN_OPTIONS)) {
    throw new Error(`Unsupported algorithm (${algorithm})`);
  }
  const options = KEY_GEN_OPTIONS[algorithm];
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  return generateKeyPairAsync(options.type as any, options.options);
}
