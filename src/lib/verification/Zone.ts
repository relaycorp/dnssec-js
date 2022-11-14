import { DsData } from '../rdata/DsData';
import { VerificationResult } from './VerificationResult';
import { Message } from '../dns/Message';
import { DnskeyData } from '../rdata/DnskeyData';
import { SecurityStatus } from './SecurityStatus';
import { RCode } from '../dns/RCode';
import { DnssecRecordType } from '../DnssecRecordType';
import { DnskeyRecord, DsRecord } from '../dnssecRecords';
import { SignedRRSet } from './SignedRRSet';
import { DNSClass } from '../dns/DNSClass';
import { DatePeriod } from './DatePeriod';

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
    if (dnskeyMessage.header.rcode !== RCode.NoError) {
      return {
        status: SecurityStatus.BOGUS,
        reasonChain: [`Expected DNSKEY rcode to be NOERROR (0; got ${dnskeyMessage.header.rcode})`],
      };
    }

    const dnskeySignedRrset = SignedRRSet.initFromRecords(
      { name: zoneName, class: DNSClass.IN, type: DnssecRecordType.DNSKEY },
      dnskeyMessage.answers,
    );

    let dnskeys: readonly DnskeyRecord[];
    try {
      dnskeys = dnskeySignedRrset.rrset.records.map((record) => ({
        data: DnskeyData.deserialise(record.dataSerialised),
        record,
      }));
    } catch (_) {
      return { status: SecurityStatus.BOGUS, reasonChain: ['Found malformed DNSKEY rdata'] };
    }
    const zskDnskeys = dnskeys.filter((k) => dsData.some((ds) => ds.verifyDnskey(k)));

    if (zskDnskeys.length === 0) {
      return { status: SecurityStatus.BOGUS, reasonChain: ['No DNSKEY matched specified DS(s)'] };
    }

    if (!dnskeySignedRrset.verify(zskDnskeys, datePeriod)) {
      return { status: SecurityStatus.BOGUS, reasonChain: ['No valid RRSig was found'] };
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
    if (dsMessage.header.rcode !== RCode.NoError) {
      return {
        status: SecurityStatus.BOGUS,
        reasonChain: [`Expected DS rcode to be NOERROR (0; got ${dsMessage.header.rcode})`],
      };
    }

    const dsSignedRrset = SignedRRSet.initFromRecords(
      { name: zoneName, class: DNSClass.IN, type: DnssecRecordType.DS },
      dsMessage.answers,
    );

    if (!dsSignedRrset.verify(this.dnskeys, datePeriod, this.name)) {
      return {
        status: SecurityStatus.BOGUS,
        reasonChain: ['Could not find at least one valid DS record'],
      };
    }

    let dsRecords: readonly DsRecord[];
    try {
      dsRecords = dsSignedRrset.rrset.records.map((record) => ({
        data: DsData.deserialise(record.dataSerialised),
        record,
      }));
    } catch (_) {
      return { status: SecurityStatus.BOGUS, reasonChain: ['Found malformed DS rdata'] };
    }

    const dsData = dsRecords.map((r) => r.data);
    return Zone.init(zoneName, dnskeyMessage, dsData, datePeriod);
  }
}
