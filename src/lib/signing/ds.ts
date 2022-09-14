import { createHash, KeyObject } from 'node:crypto';

import { DigestAlgorithm } from '../DigestAlgorithm';
import { derSerialisePublicKey, getDNSSECAlgorithm } from './utils';

function getNodejsHashAlgorithm(algorithm: DigestAlgorithm): string {
  switch (algorithm) {
    case DigestAlgorithm.SHA1:
      return 'sha1';
    case DigestAlgorithm.SHA256:
      return 'sha256';
    case DigestAlgorithm.SHA384:
      return 'sha384';
    default:
      throw new Error(`Unsupported hashing algorithm ${algorithm}`);
  }
}

function hashKey(publicKey: KeyObject, digestAlgorithm: DigestAlgorithm): Buffer {
  const hashName = getNodejsHashAlgorithm(digestAlgorithm);
  const hash = createHash(hashName);
  hash.update(derSerialisePublicKey(publicKey));
  return hash.digest();
}

export function serialiseDsRdata(
  keyTag: number,
  publicKey: KeyObject,
  digestAlgorithm: DigestAlgorithm,
): Buffer {
  const digest = hashKey(publicKey, digestAlgorithm);
  const data = Buffer.alloc(4 + digest.byteLength);

  data.writeUInt16BE(keyTag, 0);

  // Algorithm
  const algorithm = getDNSSECAlgorithm(publicKey);
  data.writeUInt8(algorithm, 2);

  data.writeUInt8(digestAlgorithm, 3);

  digest.copy(data, 4);

  return data;
}
