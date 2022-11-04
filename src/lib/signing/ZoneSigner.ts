import { KeyObject } from 'node:crypto';
import { setMilliseconds } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { Record } from '../dns/Record';
import { DNSClass } from '../dns/DNSClass';
import { generateKeyPairAsync, getKeyGenOptions } from './keyGen';
import { DigestType } from '../DigestType';
import { DnssecRecordType } from '../DnssecRecordType';
import { RRSet } from '../dns/RRSet';
import { DnskeyFlags } from '../DnskeyFlags';
import { DnskeyData } from '../rdata/DnskeyData';
import { DsData } from '../rdata/DsData';
import { hashPublicKey } from '../utils/crypto';
import { RrsigData } from '../rdata/RrsigData';
import { DnskeyRecord, DsRecord, RrsigRecord } from '../dnssecRecords';

const MAX_KEY_TAG = 2 ** 16 - 1; // 2 octets (16 bits) per RFC4034 (Section 5.1)

function generateKeyTag(): number {
  return Math.floor(Math.random() * MAX_KEY_TAG);
}

export class ZoneSigner {
  public static async generate(algorithm: DnssecAlgorithm, zoneName: string): Promise<ZoneSigner> {
    const keyTag = generateKeyTag();
    const keyGenOptions = getKeyGenOptions(algorithm);
    const keyPair = await generateKeyPairAsync(keyGenOptions.type as any, keyGenOptions.options);
    return new ZoneSigner(keyTag, keyPair.privateKey, keyPair.publicKey, zoneName, algorithm);
  }

  constructor(
    public readonly keyTag: number,
    public readonly privateKey: KeyObject,
    public readonly publicKey: KeyObject,
    public readonly zoneName: string,
    public readonly algorithm: DnssecAlgorithm,
  ) {}

  public generateDnskey(
    ttl: number,
    flags: Partial<DnskeyFlags> = {},
    protocol: number = 3,
  ): DnskeyRecord {
    const finalFlags: DnskeyFlags = { zoneKey: true, secureEntryPoint: false, ...flags };
    const data = new DnskeyData(this.publicKey, protocol, this.algorithm, finalFlags);
    const record = new Record(
      this.zoneName,
      DnssecRecordType.DNSKEY,
      DNSClass.IN,
      ttl,
      data.serialise(),
    );
    return { data, record };
  }

  public generateDs(
    childLabel: string,
    ttl: number,
    digestType: DigestType = DigestType.SHA256,
  ): DsRecord {
    const digest = hashPublicKey(this.publicKey, digestType);
    const data = new DsData(this.keyTag, this.algorithm, digestType, digest);
    const record = new Record(
      `${childLabel}.${this.zoneName}`,
      DnssecRecordType.DS,
      DNSClass.IN,
      ttl,
      data.serialise(),
    );
    return { data, record };
  }

  public generateRrsig(
    rrset: RRSet,
    signatureExpiry: Date,
    signatureInception: Date = new Date(),
  ): RrsigRecord {
    const data = RrsigData.generate(
      rrset,
      setMilliseconds(signatureExpiry, 0),
      setMilliseconds(signatureInception, 0),
      this.privateKey,
      this.zoneName,
      this.keyTag,
      this.algorithm,
    );
    const record = new Record(
      rrset.name,
      DnssecRecordType.RRSIG,
      DNSClass.IN,
      rrset.ttl,
      data.serialise(),
    );
    return { record, data };
  }
}
