import { KeyObject } from 'node:crypto';
import { addSeconds, setMilliseconds } from 'date-fns';

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
import { DnskeyRecord } from '../dnssecRecords';
import { RCode } from '../dns/RCode';
import { Message } from '../dns/Message';
import { Question } from '../dns/Question';
import { DnskeyResponse, DsResponse, RrsigResponse, ZoneResponseSet } from './responses';

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
  readonly protocol: number;
}

interface DsGenerationOptions extends RecordGenerationOptions {
  readonly digestType: DigestType;
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

  public generateDnskey(options: Partial<DnskeyGenerationOptions> = {}): DnskeyResponse {
    const finalFlags: DnskeyFlags = {
      zoneKey: true,
      secureEntryPoint: false,
      ...(options.flags ?? {}),
    };
    const data = new DnskeyData(this.publicKey, options.protocol ?? 3, this.algorithm, finalFlags);
    const ttl = options.ttl ?? FIVE_MINUTES_IN_SECONDS;
    const record = new Record(
      this.zoneName,
      DnssecRecordType.DNSKEY,
      DNSClass.IN,
      ttl,
      data.serialise(),
    );
    const question = new Question(this.zoneName, DnssecRecordType.DNSKEY, DNSClass.IN);
    const rrset = RRSet.init(question, [record, ...(options.additionalDnskeys ?? [])]);
    const rrsig = this.generateRrsig(rrset, data.calculateKeyTag(), options);
    const message = new Message(
      { rcode: RCode.NoError },
      [question],
      [...rrset.records, rrsig.record],
    );
    return { data, message, record };
  }

  public generateDs(
    dnskey: DnskeyRecord,
    childZoneName: string,
    options: Partial<DsGenerationOptions> = {},
  ): DsResponse {
    const isRootZone = childZoneName === this.zoneName && this.zoneName === '.';
    if (!isRootZone && !this.isChildZone(childZoneName)) {
      throw new Error(`${childZoneName} isn't a child of ${this.zoneName}`);
    }
    const digestType = options.digestType ?? DigestType.SHA256;
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
      options.ttl ?? FIVE_MINUTES_IN_SECONDS,
      data.serialise(),
    );
    const question = new Question(childZoneName, DnssecRecordType.DS, DNSClass.IN);
    const rrsig = this.generateRrsig(RRSet.init(question, [record]), data.keyTag, options);
    const message = new Message({ rcode: RCode.NoError }, [question], [record, rrsig.record]);
    return { data, message, record };
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
      DNSClass.IN,
      rrset.ttl,
      data.serialise(),
    );
    const message = new Message(
      { rcode: RCode.NoError },
      [new Question(rrset.name, rrset.type, rrset.class_)],
      [...rrset.records, record],
    );
    return { data, message, record };
  }

  public generateZoneResponses(
    parent: ZoneSigner,
    options: Partial<{
      readonly dnskey: Partial<DnskeyGenerationOptions>;
      readonly ds: Partial<DsGenerationOptions>;
    }> = {},
  ): ZoneResponseSet {
    const dnskey = this.generateDnskey(options.dnskey);
    const ds = parent.generateDs(dnskey, this.zoneName, options.ds);
    return { ds, dnskey };
  }

  private isChildZone(zoneName: string): boolean {
    if (this.zoneName === '.') {
      return true;
    }
    return zoneName.endsWith(`.${this.zoneName}`);
  }
}
