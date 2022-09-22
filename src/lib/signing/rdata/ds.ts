import { KeyObject } from 'node:crypto';

import { DigestType } from '../../DigestType';
import { getDNSSECAlgoFromKey } from '../utils';
import { hashPublicKey } from '../../utils/crypto';

export function serialiseDsRdata(
  keyTag: number,
  publicKey: KeyObject,
  digestType: DigestType,
): Buffer {
  const digest = hashPublicKey(publicKey, digestType);
  const data = Buffer.alloc(4 + digest.byteLength);

  data.writeUInt16BE(keyTag, 0);

  // Algorithm
  const algorithm = getDNSSECAlgoFromKey(publicKey);
  data.writeUInt8(algorithm, 2);

  data.writeUInt8(digestType, 3);

  digest.copy(data, 4);

  return data;
}
