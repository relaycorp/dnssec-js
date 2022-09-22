import { createHash, KeyObject } from 'node:crypto';

import { DigestType } from '../DigestType';

export function getNodejsHashAlgo(algorithm: DigestType): string {
  switch (algorithm) {
    case DigestType.SHA1:
      return 'sha1';
    case DigestType.SHA256:
      return 'sha256';
    case DigestType.SHA384:
      return 'sha384';
    default:
      throw new Error(`Unsupported hashing algorithm ${algorithm}`);
  }
}

export function derSerialisePublicKey(publicKey: KeyObject): Buffer {
  return publicKey.export({ format: 'der', type: 'spki' });
}

export function hashPublicKey(publicKey: KeyObject, digestAlgorithm: DigestType): Buffer {
  const hashName = getNodejsHashAlgo(digestAlgorithm);
  const hash = createHash(hashName);
  hash.update(derSerialisePublicKey(publicKey));
  return hash.digest();
}
