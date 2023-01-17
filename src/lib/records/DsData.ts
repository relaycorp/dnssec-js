/* eslint-disable @typescript-eslint/no-magic-numbers */

import type { DigestData } from '@leichtgewicht/dns-packet';

import type { DnssecAlgorithm } from '../DnssecAlgorithm.js';
import type { DigestType } from '../DigestType.js';
import { generateDigest } from '../utils/crypto/hashing.js';
import { serialiseName } from '../utils/dns/name.js';

import type { DnskeyRecord } from './dnssecRecords.js';
import type { DnssecRecordData } from './DnssecRecordData.js';

export class DsData implements DnssecRecordData {
  public static initFromPacket(packet: DigestData): DsData {
    return new DsData(
      packet.keyTag,
      packet.algorithm,
      packet.digestType,
      Buffer.from(packet.digest),
    );
  }

  public static calculateDnskeyDigest(dnskey: DnskeyRecord, digestType: DigestType): Buffer {
    const nameSerialised = serialiseName(dnskey.record.name);
    const plaintext = Buffer.concat([nameSerialised, dnskey.record.dataSerialised]);
    return generateDigest(plaintext, digestType);
  }

  public constructor(
    public readonly keyTag: number,
    public readonly algorithm: DnssecAlgorithm,
    public readonly digestType: DigestType,
    public readonly digest: Buffer,
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
