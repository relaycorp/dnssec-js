import { Parser } from 'binary-parser';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { DigestType } from '../DigestType';
import { InvalidRdataError } from '../errors';
import { DnskeyData } from './DnskeyData';
import { hashPublicKey } from '../utils/crypto';
import { DnssecRecordData } from './DnssecRecordData';

const PARSER = new Parser()
  .endianness('big')
  .uint16('keyTag')
  .uint8('algorithm')
  .uint8('digestType')
  .buffer('digest', { readUntil: 'eof' });

export class DsData implements DnssecRecordData {
  static deserialise(serialisation: Buffer): DsData {
    let parsingResult: any;
    try {
      parsingResult = PARSER.parse(serialisation);
    } catch (_) {
      throw new InvalidRdataError('DS data is malformed');
    }
    if (parsingResult.digest.byteLength === 0) {
      throw new InvalidRdataError('DS data is missing digest');
    }
    return new DsData(
      parsingResult.keyTag,
      parsingResult.algorithm,
      parsingResult.digestType,
      parsingResult.digest,
    );
  }

  constructor(
    readonly keyTag: number,
    readonly algorithm: DnssecAlgorithm,
    readonly digestType: DigestType,
    readonly digest: Buffer,
  ) {}

  public serialise(): Buffer {
    const data = Buffer.alloc(4 + this.digest.byteLength);

    data.writeUInt16BE(this.keyTag, 0);

    data.writeUInt8(this.algorithm, 2);

    data.writeUInt8(this.digestType, 3);

    this.digest.copy(data, 4);

    return data;
  }

  /**
   * Verify that the `key` corresponds to the current DS data.
   *
   * @param key
   */
  public verifyDnskey(key: DnskeyData): boolean {
    if (!key.flags.zoneKey) {
      return false;
    }

    if (key.protocol !== 3) {
      return false;
    }

    if (key.algorithm !== this.algorithm) {
      return false;
    }

    const digest = hashPublicKey(key.publicKey, this.digestType);
    return digest.equals(this.digest);
  }
}
