import { promisify } from 'node:util';
import { generateKeyPair, KeyObject } from 'node:crypto';

const generateKeyPairAsync = promisify(generateKeyPair);

interface KeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

export async function generateRSAKeyPair(modulusLength = 2048): Promise<KeyPair> {
  return generateKeyPairAsync('rsa', { modulusLength });
}
