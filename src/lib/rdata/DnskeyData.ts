import { Parser } from 'binary-parser';
import { KeyObject } from 'node:crypto';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { DnskeyFlags } from '../DnskeyFlags';
import { InvalidRdataError } from '../errors';
import { DnssecRecordData } from './DnssecRecordData';
import { SecurityStatus } from '../verification/SecurityStatus';
import { RrsigData } from './RrsigData';
import { deserialisePublicKey, serialisePublicKey } from '../utils/keySerialisation';

const PARSER = new Parser()
  .endianness('big')
  .bit8('zoneKey')
  .bit8('secureEntryPoint')
  .uint8('protocol')
  .uint8('algorithm')
  .buffer('publicKey', { readUntil: 'eof' });

export class DnskeyData implements DnssecRecordData {
  public static deserialise(serialisation: Buffer): DnskeyData {
    let parsingResult: any;
    try {
      parsingResult = PARSER.parse(serialisation);
    } catch (_) {
      throw new InvalidRdataError('DNSKEY data is malformed');
    }
    const publicKey = deserialisePublicKey(parsingResult.publicKey, parsingResult.algorithm);
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
    const publicKeyEncoded = serialisePublicKey(this.publicKey);
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

  public verifyRrsig(rrsigData: RrsigData, referenceDate: Date): SecurityStatus {
    if (this.algorithm !== rrsigData.algorithm) {
      return SecurityStatus.BOGUS;
    }

    if (rrsigData.signatureExpiry < referenceDate) {
      return SecurityStatus.BOGUS;
    }

    if (referenceDate < rrsigData.signatureInception) {
      return SecurityStatus.BOGUS;
    }

    return SecurityStatus.SECURE;
  }
}
