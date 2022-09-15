import { KeyObject } from 'node:crypto';

import { DNSSECAlgorithm } from '../DNSSECAlgorithm';
import { Record } from '../dns/Record';
import { DNSClass } from '../dns/DNSClass';
import { DNSKEYFlags, serialiseDnskeyRdata } from './rdata/dnskey';
import { generateKeyPairAsync, getKeyGenOptions } from './keyGen';
import { serialiseDsRdata } from './rdata/ds';
import { DigestAlgorithm } from '../DigestAlgorithm';
import { RecordType } from '../dns/RecordType';
import { RRSet } from '../dns/RRSet';
import { serialiseRrsigData } from './rdata/rrsig';

const MAX_KEY_TAG = 2 ** 16 - 1; // 2 octets (16 bits) per RFC4034 (Section 5.1)

function generateKeyTag(): number {
  return Math.floor(Math.random() * MAX_KEY_TAG);
}

export class ZoneSigner {
  public static async generate(algorithm: DNSSECAlgorithm, zoneName: string): Promise<ZoneSigner> {
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

  public generateDnskey(ttl: number, flags: Partial<DNSKEYFlags> = {}): Record {
    const data = serialiseDnskeyRdata(this.publicKey, flags);
    return new Record(this.zoneName, RecordType.DNSKEY, DNSClass.IN, ttl, data);
  }

  public generateDs(
    childLabel: string,
    ttl: number,
    digestAlgorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
  ): Record {
    const data = serialiseDsRdata(this.keyTag, this.publicKey, digestAlgorithm);
    return new Record(`${childLabel}.${this.zoneName}`, RecordType.DS, DNSClass.IN, ttl, data);
  }

  public generateRrsig(
    rrset: RRSet,
    signatureExpiry: Date,
    signatureInception: Date = new Date(),
  ): Record {
    const data = serialiseRrsigData(
      rrset,
      signatureExpiry,
      signatureInception,
      this.privateKey,
      this.zoneName,
      this.keyTag,
    );
    return new Record(rrset.name, RecordType.RRSIG, DNSClass.IN, rrset.ttl, data);
  }
}
