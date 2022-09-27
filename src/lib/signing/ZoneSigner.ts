import { KeyObject } from 'node:crypto';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { Record } from '../dns/Record';
import { DNSClass } from '../dns/DNSClass';
import { generateKeyPairAsync, getKeyGenOptions } from './keyGen';
import { DigestType } from '../DigestType';
import { RecordType } from '../dns/RecordType';
import { RRSet } from '../dns/RRSet';
import { DnskeyFlags } from '../DnskeyFlags';
import { DnskeyData } from '../rdata/DnskeyData';
import { getDNSSECAlgoFromKey } from './utils';
import { DsData } from '../rdata/DsData';
import { hashPublicKey } from '../utils/crypto';
import { RrsigData } from '../rdata/RrsigData';

const MAX_KEY_TAG = 2 ** 16 - 1; // 2 octets (16 bits) per RFC4034 (Section 5.1)

function generateKeyTag(): number {
  return Math.floor(Math.random() * MAX_KEY_TAG);
}

export class ZoneSigner {
  public static async generate(algorithm: DnssecAlgorithm, zoneName: string): Promise<ZoneSigner> {
    const keyTag = generateKeyTag();
    const keyGenOptions = getKeyGenOptions(algorithm);
    const keyPair = await generateKeyPairAsync(keyGenOptions.type as any, keyGenOptions.options);
    return new ZoneSigner(keyTag, keyPair.privateKey, keyPair.publicKey, zoneName);
  }

  constructor(
    public readonly keyTag: number,
    protected readonly privateKey: KeyObject,
    public readonly publicKey: KeyObject,
    public readonly zoneName: string,
  ) {}

  public generateDnskey(
    ttl: number,
    flags: Partial<DnskeyFlags> = {},
    protocol: number = 3,
  ): Record {
    const algorithm = getDNSSECAlgoFromKey(this.publicKey);
    const finalFlags: DnskeyFlags = { zoneKey: true, secureEntryPoint: false, ...flags };
    const data = new DnskeyData(this.publicKey, protocol, algorithm, finalFlags);
    return new Record(this.zoneName, RecordType.DNSKEY, DNSClass.IN, ttl, data.serialise());
  }

  public generateDs(
    childLabel: string,
    ttl: number,
    digestType: DigestType = DigestType.SHA256,
  ): Record {
    const digest = hashPublicKey(this.publicKey, digestType);
    const algorithm = getDNSSECAlgoFromKey(this.publicKey);
    const data = new DsData(this.keyTag, algorithm, digestType, digest);
    return new Record(
      `${childLabel}.${this.zoneName}`,
      RecordType.DS,
      DNSClass.IN,
      ttl,
      data.serialise(),
    );
  }

  public generateRrsig(
    rrset: RRSet,
    signatureExpiry: Date,
    signatureInception: Date = new Date(),
  ): Record {
    const data = RrsigData.generate(
      rrset,
      signatureExpiry,
      signatureInception,
      this.privateKey,
      this.zoneName,
      this.keyTag,
    );
    return new Record(rrset.name, RecordType.RRSIG, DNSClass.IN, rrset.ttl, data.serialise());
  }
}
