import type { KeyObject } from 'node:crypto';

import { addSeconds, minutesToSeconds, setMilliseconds } from 'date-fns';

import type { DnssecAlgorithm } from '../../lib/DnssecAlgorithm';
import { DnsRecord } from '../../lib/dns/DnsRecord';
import { DnsClass } from '../../lib/dns/ianaClasses';
import { DigestType } from '../../lib/DigestType';
import { DnssecRecordType } from '../../lib/DnssecRecordType';
import { RrSet } from '../../lib/dns/RrSet';
import type { DnskeyFlags } from '../../lib/DnskeyFlags';
import { DnskeyData } from '../../lib/rdata/DnskeyData';
import { DsData } from '../../lib/rdata/DsData';
import { RrsigData } from '../../lib/rdata/RrsigData';
import type { DnskeyRecord } from '../../lib/dnssecRecords';
import { Message } from '../../lib/dns/Message';
import { Question } from '../../lib/dns/Question';
import { RCODE_IDS } from '../../lib/dns/ianaRcodes';
import { isChildZone } from '../../lib/dns/name';

import type { DnskeyResponse, DsResponse, RrsigResponse, ZoneResponseSet } from './responses';
import { generateKeyPair } from './keyGen';
import type { SignatureGenerationOptions } from './SignatureGenerationOptions';

// eslint-disable-next-line @typescript-eslint/no-magic-numbers
const FIVE_MINUTES_IN_SECONDS = minutesToSeconds(5);

interface RecordGenerationOptions extends SignatureGenerationOptions {
  readonly ttl: number;
}

interface DnskeyGenerationOptions extends RecordGenerationOptions {
  readonly additionalDnskeys: readonly DnsRecord[];
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
    const isRootZone = childZoneName === this.zoneName && this.zoneName === '.';
    if (!isRootZone && !isChildZone(this.zoneName, childZoneName)) {
      throw new Error(`${childZoneName} isn't a child of ${this.zoneName}`);
    }
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
    options: Partial<SignatureGenerationOptions> = {},
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
}
