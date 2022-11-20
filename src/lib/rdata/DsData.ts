import { DigestData } from '@leichtgewicht/dns-packet';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { DigestType } from '../DigestType';
import { generateDigest } from '../utils/crypto/hashing';
import { DnssecRecordData } from './DnssecRecordData';
import { DnskeyRecord } from '../dnssecRecords';
import { serialiseName } from '../dns/name';

export class DsData implements DnssecRecordData {
  static initFromPacket(packet: DigestData): DsData {
    return new DsData(
      packet.keyTag,
      packet.algorithm,
      packet.digestType,
      Buffer.from(packet.digest),
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
