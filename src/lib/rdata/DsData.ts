import { Parser } from 'binary-parser';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { DigestType } from '../DigestType';
import { MalformedRdataError } from '../verification/MalformedRdataError';
import { generateDigest } from '../utils/crypto';
import { DnssecRecordData } from './DnssecRecordData';
import { DnskeyRecord } from '../dnssecRecords';
import { serialiseName } from '../dns/name';

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
      throw new MalformedRdataError('DS data is malformed');
    }
    if (parsingResult.digest.byteLength === 0) {
      throw new MalformedRdataError('DS data is missing digest');
    }
    return new DsData(
      parsingResult.keyTag,
      parsingResult.algorithm,
      parsingResult.digestType,
      parsingResult.digest,
    );
  }

  static calculateDnskeyDigest(dnskey: DnskeyRecord, digestType: DigestType): Buffer {
    const nameSerialised = serialiseName(dnskey.record.name);
    const plaintext = Buffer.concat([nameSerialised, dnskey.record.dataSerialised]);
    return generateDigest(plaintext, digestType);
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
   * Verify that the `key` is a ZSK and corresponds to the current DS data and.
   *
   * @param key
   */
  public verifyDnskey(key: DnskeyRecord): boolean {
    if (!key.data.flags.zoneKey) {
      return false;
    }

    if (key.data.algorithm !== this.algorithm) {
      return false;
    }

    const digest = DsData.calculateDnskeyDigest(key, this.digestType);
    return digest.equals(this.digest);
  }
}
