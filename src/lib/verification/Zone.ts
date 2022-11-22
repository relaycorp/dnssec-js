import { DsData } from '../rdata/DsData';
import { VerificationResult } from './results';
import { Message } from '../dns/Message';
import { DnskeyData } from '../rdata/DnskeyData';
import { SecurityStatus } from './SecurityStatus';
import { DnssecRecordType } from '../DnssecRecordType';
import { DnskeyRecord } from '../dnssecRecords';
import { SignedRRSet } from './SignedRRSet';
import { DnsClass } from '../dns/ianaClasses';
import { DatePeriod } from './DatePeriod';
import { Question } from '../dns/Question';
import { RCODE_IDS } from '../dns/ianaRcodes';

/**
 * A secure zone (in DNSSEC terms).
 */
export class Zone {
  /**
   * Initialise zone.
   *
   * This is an internal utility that would normally be `protected`/`private` but we're making
   * `public` so that it can be unit-tested directly.
   *
   * @param zoneName
   * @param dnskeyMessage
   * @param dsData
   * @param datePeriod
   */
  public static init(
    zoneName: string,
    dnskeyMessage: Message,
    dsData: readonly DsData[],
    datePeriod: DatePeriod,
  ): VerificationResult<Zone> {
    if (dnskeyMessage.header.rcode !== RCODE_IDS.NoError) {
      return {
        status: SecurityStatus.INDETERMINATE,
        reasonChain: [`Expected DNSKEY rcode to be NOERROR (0; got ${dnskeyMessage.header.rcode})`],
      };
    }

    const dnskeySignedRrset = SignedRRSet.initFromRecords(
      new Question(zoneName, DnssecRecordType.DNSKEY, DnsClass.IN),
      dnskeyMessage.answers,
    );

    const dnskeys = dnskeySignedRrset.rrset.records.map((record) => ({
      data: DnskeyData.initFromPacket(record.dataFields, record.dataSerialised),
      record,
    }));
    const zskDnskeys = dnskeys.filter((k) => dsData.some((ds) => ds.verifyDnskey(k)));

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

  public verifyRrset(rrset: SignedRRSet, datePeriod: DatePeriod): boolean {
    return rrset.verify(this.dnskeys, datePeriod);
  }

  public initChild(
    zoneName: string,
    dnskeyMessage: Message,
    dsMessage: Message,
    datePeriod: DatePeriod,
  ): VerificationResult<Zone> {
    if (dsMessage.header.rcode !== RCODE_IDS.NoError) {
      return {
        status: SecurityStatus.INDETERMINATE,
        reasonChain: [`Expected DS rcode to be NOERROR (0; got ${dsMessage.header.rcode})`],
      };
    }

    const dsSignedRrset = SignedRRSet.initFromRecords(
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
      data: DsData.initFromPacket(record.dataFields),
      record,
    }));

    const dsData = dsRecords.map((r) => r.data);
    return Zone.init(zoneName, dnskeyMessage, dsData, datePeriod);
  }
}
