import { KeyObject } from 'node:crypto';
import { addSeconds, setMilliseconds } from 'date-fns';

import { DnssecAlgorithm } from '../../lib/DnssecAlgorithm';
import { Record } from '../../lib/dns/Record';
import { DnsClass } from '../../lib/dns/ianaClasses';
import { generateKeyPair } from './keyGen';
import { DigestType } from '../../lib/DigestType';
import { DnssecRecordType } from '../../lib/DnssecRecordType';
import { RRSet } from '../../lib/dns/RRSet';
import { DnskeyFlags } from '../../lib/DnskeyFlags';
import { DnskeyData } from '../../lib/rdata/DnskeyData';
import { DsData } from '../../lib/rdata/DsData';
import { RrsigData } from '../../lib/rdata/RrsigData';
import { DnskeyRecord } from '../../lib/dnssecRecords';
import { Message } from '../../lib/dns/Message';
import { Question } from '../../lib/dns/Question';
import { DnskeyResponse, DsResponse, RrsigResponse, ZoneResponseSet } from './responses';
import { RCODE_IDS } from '../../lib/dns/ianaRcodes';

const FIVE_MINUTES_IN_SECONDS = 5 * 60;

export interface SignatureGenerationOptions {
  readonly signatureInception: Date;
  readonly signatureExpiry: Date;
}

interface RecordGenerationOptions extends SignatureGenerationOptions {
  readonly ttl: number;
}

interface DnskeyGenerationOptions extends RecordGenerationOptions {
  readonly additionalDnskeys: readonly Record[];
  readonly flags: Partial<DnskeyFlags>;
}

interface DsGenerationOptions extends RecordGenerationOptions {
  readonly digestType: DigestType;
}

export class ZoneSigner {
  public static async generate(algorithm: DnssecAlgorithm, zoneName: string): Promise<ZoneSigner> {
    const keyPair = await generateKeyPair(algorithm);
    return new ZoneSigner(keyPair.privateKey, keyPair.publicKey, zoneName, algorithm);
  }

  constructor(
    public readonly privateKey: KeyObject,
    public readonly publicKey: KeyObject,
    public readonly zoneName: string,
    public readonly algorithm: DnssecAlgorithm,
  ) {}

  public generateDnskey(options: Partial<DnskeyGenerationOptions> = {}): DnskeyResponse {
    const finalFlags: DnskeyFlags = {
      zoneKey: true,
      secureEntryPoint: false,
      ...(options.flags ?? {}),
    };
    const data = new DnskeyData(this.publicKey, this.algorithm, finalFlags);
    const ttl = options.ttl ?? FIVE_MINUTES_IN_SECONDS;
    const record = new Record(
      this.zoneName,
      DnssecRecordType.DNSKEY,
      DnsClass.IN,
      ttl,
      data.serialise(),
    );
    const rrset = RRSet.init(record.makeQuestion(), [record, ...(options.additionalDnskeys ?? [])]);
    const rrsig = this.generateRrsig(rrset, data.calculateKeyTag(), options);
    return { data, message: rrsig.message, record, rrsig };
  }

  public generateDs(
    childDnskey: DnskeyRecord,
    childZoneName: string,
    dnskeyTag: number,
    options: Partial<DsGenerationOptions> = {},
  ): DsResponse {
    const isRootZone = childZoneName === this.zoneName && this.zoneName === '.';
    if (!isRootZone && !this.isChildZone(childZoneName)) {
      throw new Error(`${childZoneName} isn't a child of ${this.zoneName}`);
    }
    const digestType = options.digestType ?? DigestType.SHA256;
    const data = new DsData(
      childDnskey.data.calculateKeyTag(),
      childDnskey.data.algorithm,
      digestType,
      DsData.calculateDnskeyDigest(childDnskey, digestType),
    );
    const record = new Record(
      childZoneName,
      DnssecRecordType.DS,
      DnsClass.IN,
      options.ttl ?? FIVE_MINUTES_IN_SECONDS,
      data.serialise(),
    );
    const rrsig = this.generateRrsig(
      RRSet.init(record.makeQuestion(), [record]),
      dnskeyTag,
      options,
    );
    return { data, message: rrsig.message, record, rrsig };
  }

  public generateRrsig(
    rrset: RRSet,
    keyTag: number,
    options: Partial<SignatureGenerationOptions> = {},
  ): RrsigResponse {
    if (rrset.name !== this.zoneName && !this.isChildZone(rrset.name)) {
      throw new Error(`RRset for ${rrset.name} isn't a child of ${this.zoneName}`);
    }
    const signatureInception = options.signatureInception ?? new Date();
    const signatureExpiry = options.signatureExpiry ?? addSeconds(signatureInception, rrset.ttl);
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
      DnsClass.IN,
      rrset.ttl,
      data.serialise(),
    );
    const message = new Message(
      { rcode: RCODE_IDS.NoError },
      [new Question(rrset.name, rrset.type, rrset.class_)],
      [...rrset.records, record],
    );
    return { data, message, record };
  }

  public generateZoneResponses(
    parent: ZoneSigner,
    parentDnskeyTag: number | null,
    options: Partial<{
      readonly dnskey: Partial<DnskeyGenerationOptions>;
      readonly ds: Partial<DsGenerationOptions>;
    }> = {},
  ): ZoneResponseSet {
    const dnskey = this.generateDnskey(options.dnskey);
    const ds = parent.generateDs(
      dnskey,
      this.zoneName,
      parentDnskeyTag ?? dnskey.data.calculateKeyTag(),
      options.ds,
    );
    return { ds, dnskey };
  }

  private isChildZone(zoneName: string): boolean {
    if (this.zoneName === '.') {
      return true;
    }
    return zoneName.endsWith(`.${this.zoneName}`);
  }
}
