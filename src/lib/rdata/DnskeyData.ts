import { Parser } from 'binary-parser';
import { createPublicKey, KeyObject } from 'node:crypto';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { DnskeyFlags } from '../DnskeyFlags';
import { InvalidRdataError } from '../errors';
import { RecordData } from './RecordData';
import { derSerialisePublicKey } from '../utils/crypto';

const PARSER = new Parser()
  .endianness('big')
  .bit8('zoneKey')
  .bit8('secureEntryPoint')
  .uint8('protocol')
  .uint8('algorithm')
  .buffer('publicKey', { readUntil: 'eof' });

export class DnskeyData implements RecordData {
  public static deserialise(serialisation: Buffer): DnskeyData {
    let parsingResult: any;
    try {
      parsingResult = PARSER.parse(serialisation);
    } catch (_) {
      throw new InvalidRdataError('DNSKEY data is malformed');
    }
    const publicKey = parsePublicKey(parsingResult.publicKey);
    const flags: DnskeyFlags = {
      zoneKey: !!parsingResult.zoneKey,
      secureEntryPoint: !!parsingResult.secureEntryPoint,
    };
    return new DnskeyData(publicKey, parsingResult.protocol, parsingResult.algorithm, flags);
  }

  constructor(
    public readonly publicKey: KeyObject,
    public readonly protocol: number,
    public readonly algorithm: DnssecAlgorithm,
    public readonly flags: DnskeyFlags,
  ) {}

  public serialise(): Buffer {
    const publicKeyEncoded = derSerialisePublicKey(this.publicKey);
    const data = Buffer.alloc(4 + publicKeyEncoded.byteLength);

    if (this.flags.zoneKey) {
      data.writeUInt8(0b00000001, 0);
    }
    if (this.flags.secureEntryPoint) {
      data.writeUInt8(0b00000001, 1);
    }

    data.writeUInt8(this.protocol, 2);

    data.writeUInt8(this.algorithm, 3);

    publicKeyEncoded.copy(data, 4);
    return data;
  }
}

function parsePublicKey(publicKeySerialized: Buffer): KeyObject {
  if (publicKeySerialized.byteLength === 0) {
    throw new InvalidRdataError('DNSKEY data is missing public key');
  }
  return createPublicKey({
    key: publicKeySerialized,
    format: 'der',
    type: 'spki',
  });
}
