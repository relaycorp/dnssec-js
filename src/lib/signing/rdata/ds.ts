import { createHash, KeyObject } from 'node:crypto';

import { DigestAlgorithm } from '../../DigestAlgorithm';
import { derSerialisePublicKey, getDNSSECAlgoFromKey, getNodejsHashAlgo } from '../utils';

export function serialiseDsRdata(
  keyTag: number,
  publicKey: KeyObject,
  digestAlgorithm: DigestAlgorithm,
): Buffer {
  const digest = hashKey(publicKey, digestAlgorithm);
  const data = Buffer.alloc(4 + digest.byteLength);

  data.writeUInt16BE(keyTag, 0);

  // Algorithm
  const algorithm = getDNSSECAlgoFromKey(publicKey);
  data.writeUInt8(algorithm, 2);

  data.writeUInt8(digestAlgorithm, 3);

  digest.copy(data, 4);

  return data;
}

function hashKey(publicKey: KeyObject, digestAlgorithm: DigestAlgorithm): Buffer {
  const hashName = getNodejsHashAlgo(digestAlgorithm);
  const hash = createHash(hashName);
  hash.update(derSerialisePublicKey(publicKey));
  return hash.digest();
}
