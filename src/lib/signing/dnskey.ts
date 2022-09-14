import { KeyObject } from 'node:crypto';
import { derSerialisePublicKey, getDNSSECAlgorithm } from './utils';

export interface DNSKEYFlags {
  readonly zoneKey: boolean;
  readonly secureEntryPoint: boolean;
}

export function serialiseDnskeyRdata(publicKey: KeyObject, flags: Partial<DNSKEYFlags>): Buffer {
  const publicKeyEncoded = derSerialisePublicKey(publicKey);
  const data = Buffer.alloc(4 + publicKeyEncoded.byteLength);

  if (flags.zoneKey ?? true) {
    data.writeUInt8(0b00000001, 0);
  }
  if (flags.secureEntryPoint) {
    data.writeUInt8(0b00000001, 1);
  }

  // Protocol
  data.writeUInt8(3, 2);

  // Algorithm
  const algorithm = getDNSSECAlgorithm(publicKey);
  data.writeUInt8(algorithm, 3);

  publicKeyEncoded.copy(data, 4);
  return data;
}
