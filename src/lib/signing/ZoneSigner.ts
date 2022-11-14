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
import { RrsigData } from '../rdata/RrsigData';
import { DnskeyRecord, DsRecord, RrsigRecord } from '../dnssecRecords';
import { Zone } from '../verification/Zone';
import { RCode } from '../dns/RCode';
import { Message } from '../dns/Message';
import { SuccessfulResult } from '../verification/VerificationResult';
import { DatePeriod } from '../verification/DatePeriod';

interface ZoneGenerationOptions {
  readonly parent: ZoneSigner;
  readonly additionalDnskeys: readonly Record[];
}

export class ZoneSigner {
  public static async generate(algorithm: DnssecAlgorithm, zoneName: string): Promise<ZoneSigner> {
    const keyGenOptions = getKeyGenOptions(algorithm);
    const keyPair = await generateKeyPairAsync(keyGenOptions.type as any, keyGenOptions.options);
    return new ZoneSigner(keyPair.privateKey, keyPair.publicKey, zoneName, algorithm);
  }

  constructor(
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
    dnskey: DnskeyRecord,
    childZoneName: string,
    ttl: number,
    digestType: DigestType = DigestType.SHA256,
  ): DsRecord {
    const isRootZone = childZoneName === this.zoneName && this.zoneName === '.';
    if (!isRootZone && !this.isChildZone(childZoneName)) {
      throw new Error(`${childZoneName} isn't a child of ${this.zoneName}`);
    }
    const digest = DsData.calculateDnskeyDigest(dnskey, digestType);
    const data = new DsData(
      dnskey.data.calculateKeyTag(),
      dnskey.data.algorithm,
      digestType,
      digest,
    );
    const record = new Record(
      childZoneName,
      DnssecRecordType.DS,
      DNSClass.IN,
      ttl,
      data.serialise(),
    );
    return { data, record };
  }

  public generateRrsig(
    rrset: RRSet,
    keyTag: number,
    signatureExpiry: Date,
    signatureInception: Date = new Date(),
  ): RrsigRecord {
    if (rrset.name !== this.zoneName && !this.isChildZone(rrset.name)) {
      throw new Error(`RRset for ${rrset.name} isn't a child of ${this.zoneName}`);
    }
    const data = RrsigData.generate(
      rrset,
      setMilliseconds(signatureExpiry, 0),
      setMilliseconds(signatureInception, 0),
      this.privateKey,
      this.zoneName,
      keyTag,
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

  public generateZone(rrsigExpiryDate: Date, options: Partial<ZoneGenerationOptions> = {}): Zone {
    const dnskey = this.generateDnskey(42, { zoneKey: true });
    const dnskeyRecords = [...(options.additionalDnskeys ?? []), dnskey.record];
    const dnskeyRrsig = this.generateRrsig(
      RRSet.init(
        { class: DNSClass.IN, name: this.zoneName, type: DnssecRecordType.DNSKEY },
        dnskeyRecords,
      ),
      dnskey.data.calculateKeyTag(),
      rrsigExpiryDate,
    );
    const dnskeyMessage = new Message({ rcode: RCode.NoError }, [
      ...dnskeyRecords,
      dnskeyRrsig.record,
    ]);
    const ds = (options.parent ?? this).generateDs(dnskey, this.zoneName, 42);
    const datePeriod = DatePeriod.init(dnskeyRrsig.data.signatureInception, rrsigExpiryDate);
    const zoneResult = Zone.init(this.zoneName, dnskeyMessage, [ds.data], datePeriod);
    return (zoneResult as SuccessfulResult<Zone>).result;
  }

  private isChildZone(zoneName: string): boolean {
    if (this.zoneName === '.') {
      return true;
    }
    return zoneName.endsWith(`.${this.zoneName}`);
  }
}
