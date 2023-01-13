import type { DigestData, DNSKeyData } from '@leichtgewicht/dns-packet';

import { DsData } from './records/DsData.js';
import type { VerificationResult } from './securityStatusResults.js';
import type { Message } from './utils/dns/Message.js';
import { DnskeyData } from './records/DnskeyData.js';
import { SecurityStatus } from './SecurityStatus.js';
import { DnssecRecordType } from './records/DnssecRecordType.js';
import type { DnskeyRecord } from './records/dnssecRecords.js';
import { SignedRrSet } from './SignedRrSet.js';
import { DnsClass } from './utils/dns/ianaClasses.js';
import type { DatePeriod } from './DatePeriod.js';
import { Question } from './utils/dns/Question.js';
import { RCODE_IDS } from './utils/dns/ianaRcodes.js';

/**
 * A secure zone (in DNSSEC terms).
 */
export class Zone {
  /**
   * Initialise zone.
   *
   * This is an internal utility that would normally be `protected`/`private` but we're making
   * `public` so that it can be unit-tested directly.
   */
  public static init(
    zoneName: string,
    dnskeyMessage: Message,
    dsData: readonly DsData[],
    datePeriod: DatePeriod,
  ): VerificationResult<Zone> {
    if (dnskeyMessage.header.rcode !== RCODE_IDS.NOERROR) {
      return {
        status: SecurityStatus.INSECURE,
        reasonChain: [`Expected DNSKEY rcode to be NOERROR (0; got ${dnskeyMessage.header.rcode})`],
      };
    }

    const dnskeySignedRrset = SignedRrSet.initFromRecords(
      new Question(zoneName, DnssecRecordType.DNSKEY, DnsClass.IN),
      dnskeyMessage.answers,
    );

    if (dnskeySignedRrset.rrsigs.length === 0) {
      return {
        status: SecurityStatus.INDETERMINATE,
        reasonChain: ['DNSKEY RR is unsigned'],
      };
    }

    const dnskeys = dnskeySignedRrset.rrset.records.map((record) => ({
      data: DnskeyData.initFromPacket(record.dataFields as DNSKeyData, record.dataSerialised),
      record,
    }));
    const zskDnskeys = dnskeys.filter((dnskey) => dsData.some((ds) => ds.verifyDnskey(dnskey)));

    if (zskDnskeys.length === 0) {
      return { status: SecurityStatus.BOGUS, reasonChain: ['No DNSKEY matched specified DS(s)'] };
    }

    if (!dnskeySignedRrset.verify(zskDnskeys, datePeriod)) {
      return { status: SecurityStatus.BOGUS, reasonChain: ['No valid DNSKEY RRSig was found'] };
    }

    return {
      status: SecurityStatus.SECURE,
      result: new Zone(zoneName, dnskeys),
    };
  }

  public static initRoot(
    dnskeyMessage: Message,
    dsData: readonly DsData[],
    datePeriod: DatePeriod,
  ): VerificationResult<Zone> {
    return Zone.init('.', dnskeyMessage, dsData, datePeriod);
  }

  protected constructor(
    public readonly name: string,
    public readonly dnskeys: readonly DnskeyRecord[],
  ) {}

  public verifyRrset(rrset: SignedRrSet, datePeriod: DatePeriod): boolean {
    return rrset.verify(this.dnskeys, datePeriod);
  }

  public initChild(
    zoneName: string,
    dnskeyMessage: Message,
    dsMessage: Message,
    datePeriod: DatePeriod,
  ): VerificationResult<Zone> {
    if (dsMessage.header.rcode !== RCODE_IDS.NOERROR) {
      return {
        status: SecurityStatus.INSECURE,
        reasonChain: [`Expected DS rcode to be NOERROR (0; got ${dsMessage.header.rcode})`],
      };
    }

    const dsSignedRrset = SignedRrSet.initFromRecords(
      new Question(zoneName, DnssecRecordType.DS, DnsClass.IN),
      dsMessage.answers,
    );

    if (!dsSignedRrset.verify(this.dnskeys, datePeriod, this.name)) {
      return {
        status: SecurityStatus.BOGUS,
        reasonChain: ['Could not find at least one valid DS record'],
      };
    }

    const dsRecords = dsSignedRrset.rrset.records.map((record) => ({
      data: DsData.initFromPacket(record.dataFields as DigestData),
      record,
    }));

    const dsData = dsRecords.map((ds) => ds.data);
    return Zone.init(zoneName, dnskeyMessage, dsData, datePeriod);
  }
}
