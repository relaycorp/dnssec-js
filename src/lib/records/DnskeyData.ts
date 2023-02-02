/* eslint-disable @typescript-eslint/no-magic-numbers */

import type { KeyObject } from 'node:crypto';

import type { DNSKeyData } from '@leichtgewicht/dns-packet';

import type { DnssecAlgorithm } from '../DnssecAlgorithm.js';
import { deserialisePublicKey, serialisePublicKey } from '../utils/crypto/keySerialisation.js';
import type { DatePeriod } from '../dates.js';

import type { DnskeyFlags } from './DnskeyFlags.js';
import type { DnssecRecordData } from './DnssecRecordData.js';
import type { RrsigData } from './RrsigData.js';

const ZONE_KEY_MASK = 0b0000_0001_0000_0000;
const SECURE_ENTRY_POINT_MASK = 0b0000_0000_0000_0001;

/**
 * Return key tag for DNSKEY.
 *
 * RFC 4034 (Appendix B) requires using one of two algorithms depending on the DNSSEC crypto
 * algorithm used, but since one of them is for Algorithm 1 (RSA/MD5) -- which we won't
 * support -- we're only supporting one key tag algorithm.
 */
function calculateKeyTag(rdata: Buffer) {
  // Algorithm pretty much copy/pasted from https://www.rfc-editor.org/rfc/rfc4034#appendix-B
  let accumulator = 0;
  for (let index = 0; index < rdata.byteLength; ++index) {
    accumulator += index & 1 ? rdata[index] : rdata[index] << 8;
  }
  accumulator += (accumulator >> 16) & 0xff_ff;
  return accumulator & 0xff_ff;
}

export class DnskeyData implements DnssecRecordData {
  public static initFromPacket(packet: DNSKeyData, packetSerialised: Buffer): DnskeyData {
    const publicKey = deserialisePublicKey(packet.key as unknown as Buffer, packet.algorithm);
    const flags: DnskeyFlags = {
      zoneKey: Boolean(packet.flags & ZONE_KEY_MASK),
      secureEntryPoint: Boolean(packet.flags & SECURE_ENTRY_POINT_MASK),
    };
    const keyTag = calculateKeyTag(packetSerialised);
    return new DnskeyData(publicKey, packet.algorithm, flags, keyTag);
  }

  public constructor(
    public readonly publicKey: KeyObject,
    public readonly algorithm: DnssecAlgorithm,
    public readonly flags: DnskeyFlags,
    public readonly keyTag: number | null = null,
  ) {}

  public serialise(): Buffer {
    const publicKeyEncoded = serialisePublicKey(this.publicKey, this.algorithm);
    const data = Buffer.alloc(4 + publicKeyEncoded.byteLength);

    if (this.flags.zoneKey) {
      data.writeUInt8(0b0000_0001, 0);
    }
    if (this.flags.secureEntryPoint) {
      data.writeUInt8(0b0000_0001, 1);
    }

    data.writeUInt8(3, 2);

    data.writeUInt8(this.algorithm, 3);

    publicKeyEncoded.copy(data, 4);
    return data;
  }

  public calculateKeyTag(): number {
    if (this.keyTag !== null) {
      return this.keyTag;
    }

    // We should probably cache the calculation, but that'd only help in situations where we're
    // *generating* DNSKEYs (e.g., in test suites).
    const rdata = this.serialise();
    return calculateKeyTag(rdata);
  }

  public verifyRrsig(rrsigData: RrsigData, datePeriod: DatePeriod): boolean {
    if (this.calculateKeyTag() !== rrsigData.keyTag) {
      return false;
    }

    if (this.algorithm !== rrsigData.algorithm) {
      return false;
    }

    return datePeriod.overlaps(rrsigData.signatureInception, rrsigData.signatureExpiry);
  }
}
