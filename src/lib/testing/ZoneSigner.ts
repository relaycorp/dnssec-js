import type { KeyObject } from 'node:crypto';

import { addSeconds, minutesToSeconds, setMilliseconds } from 'date-fns';

import type { DnssecAlgorithm } from '../DnssecAlgorithm.js';
import { DnsRecord } from '../utils/dns/DnsRecord.js';
import { DnsClass } from '../utils/dns/ianaClasses.js';
import { DigestType } from '../DigestType.js';
import { DnssecRecordType } from '../records/DnssecRecordType.js';
import { RrSet } from '../utils/dns/RrSet.js';
import type { DnskeyFlags } from '../records/DnskeyFlags.js';
import { DnskeyData } from '../records/DnskeyData.js';
import { DsData } from '../records/DsData.js';
import { RrsigData } from '../records/RrsigData.js';
import type { DnskeyRecord } from '../records/dnssecRecords.js';
import { Message } from '../utils/dns/Message.js';
import { Question } from '../utils/dns/Question.js';
import { RCODE_IDS } from '../utils/dns/ianaRcodes.js';
import type {
  DnskeyResponse,
  DsResponse,
  RrsigResponse,
  ZoneResponseSet,
} from '../dnssecResponses.js';
import { generateKeyPair } from '../utils/crypto/keyGen.js';

import type { SignatureOptions } from './SignatureOptions.js';

// eslint-disable-next-line @typescript-eslint/no-magic-numbers
const FIVE_MINUTES_IN_SECONDS = minutesToSeconds(5);

interface RecordGenerationOptions extends SignatureOptions {
  readonly ttl: number;
}

interface DsGenerationOptions extends RecordGenerationOptions {
  readonly digestType: DigestType;
}

export interface DnskeyGenerationOptions extends RecordGenerationOptions {
  readonly additionalDnskeys: readonly DnsRecord[];
  readonly flags: Partial<DnskeyFlags>;
}

export class ZoneSigner {
  public static async generate(algorithm: DnssecAlgorithm, zoneName: string): Promise<ZoneSigner> {
    const keyPair = await generateKeyPair(algorithm);
    return new ZoneSigner(keyPair.privateKey, keyPair.publicKey, zoneName, algorithm);
  }

  public constructor(
    public readonly privateKey: KeyObject,
    public readonly publicKey: KeyObject,
    public readonly zoneName: string,
    public readonly algorithm: DnssecAlgorithm,
  ) {}

  public generateDnskey(options: Partial<DnskeyGenerationOptions> = {}): DnskeyResponse {
    const finalFlags: DnskeyFlags = {
      zoneKey: true,
      secureEntryPoint: false,
      ...options.flags,
    };
    const data = new DnskeyData(this.publicKey, this.algorithm, finalFlags);
    const ttl = options.ttl ?? FIVE_MINUTES_IN_SECONDS;
    const record = new DnsRecord(
      this.zoneName,
      DnssecRecordType.DNSKEY,
      DnsClass.IN,
      ttl,
      data.serialise(),
    );
    const rrset = RrSet.init(record.makeQuestion(), [record, ...(options.additionalDnskeys ?? [])]);
    const rrsig = this.generateRrsig(rrset, data.calculateKeyTag(), options);
    return { data, message: rrsig.message, record, rrsig };
  }

  public generateDs(
    childDnskey: DnskeyRecord,
    childZoneName: string,
    dnskeyTag: number,
    options: Partial<DsGenerationOptions> = {},
  ): DsResponse {
    const digestType = options.digestType ?? DigestType.SHA256;
    const data = new DsData(
      childDnskey.data.calculateKeyTag(),
      childDnskey.data.algorithm,
      digestType,
      DsData.calculateDnskeyDigest(childDnskey, digestType),
    );
    const record = new DnsRecord(
      childZoneName,
      DnssecRecordType.DS,
      DnsClass.IN,
      options.ttl ?? FIVE_MINUTES_IN_SECONDS,
      data.serialise(),
    );
    const rrsig = this.generateRrsig(
      RrSet.init(record.makeQuestion(), [record]),
      dnskeyTag,
      options,
    );
    return { data, message: rrsig.message, record, rrsig };
  }

  public generateRrsig(
    rrset: RrSet,
    keyTag: number,
    options: Partial<SignatureOptions>,
  ): RrsigResponse {
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
    const record = new DnsRecord(
      rrset.name,
      DnssecRecordType.RRSIG,
      DnsClass.IN,
      rrset.ttl,
      data.serialise(),
    );
    const message = new Message(
      { rcode: RCODE_IDS.NOERROR },
      [new Question(rrset.name, rrset.type, rrset.classId)],
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
    }>,
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
}
