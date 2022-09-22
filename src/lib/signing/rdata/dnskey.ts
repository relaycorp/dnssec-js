import { KeyObject } from 'node:crypto';

import { getDNSSECAlgoFromKey } from '../utils';
import { DNSKEYFlags } from '../../DNSKEYFlags';
import { derSerialisePublicKey } from '../../utils/crypto';

export function serialiseDnskeyRdata(
  publicKey: KeyObject,
  flags: Partial<DNSKEYFlags>,
  protocol: number,
): Buffer {
  const publicKeyEncoded = derSerialisePublicKey(publicKey);
  const data = Buffer.alloc(4 + publicKeyEncoded.byteLength);

  if (flags.zoneKey ?? true) {
    data.writeUInt8(0b00000001, 0);
  }
  if (flags.secureEntryPoint) {
    data.writeUInt8(0b00000001, 1);
  }

  // Protocol
  data.writeUInt8(protocol, 2);

  // Algorithm
  const algorithm = getDNSSECAlgoFromKey(publicKey);
  data.writeUInt8(algorithm, 3);

  publicKeyEncoded.copy(data, 4);
  return data;
}
