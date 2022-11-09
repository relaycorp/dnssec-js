import { DsData } from '../rdata/DsData';
import { VerificationResult } from './VerificationResult';
import { Message } from '../dns/Message';
import { DnskeyData } from '../rdata/DnskeyData';
import { SecurityStatus } from './SecurityStatus';
import { RCode } from '../dns/RCode';
import { DnssecRecordType } from '../DnssecRecordType';
import { DnskeyRecord } from '../dnssecRecords';
import { SignedRRSet } from './SignedRRSet';
import { DNSClass } from '../dns/DNSClass';

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
   * @param referenceDate
   */
  public static init(
    zoneName: string,
    dnskeyMessage: Message,
    dsData: readonly DsData[],
    referenceDate: Date,
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
      return { status: SecurityStatus.BOGUS, reasonChain: ['Found malformed DNSKEY'] };
    }
    const zskDnskeys = dnskeys.filter((k) => dsData.some((ds) => ds.verifyDnskey(k)));

    if (zskDnskeys.length === 0) {
      return { status: SecurityStatus.BOGUS, reasonChain: ['No DNSKEY matched specified DS(s)'] };
    }

    if (!dnskeySignedRrset.verify(zskDnskeys, referenceDate)) {
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
    referenceDate: Date,
  ): VerificationResult<Zone> {
    return Zone.init('.', dnskeyMessage, dsData, referenceDate);
  }

  protected constructor(
    public readonly name: string,
    public readonly dnskeys: readonly DnskeyRecord[],
  ) {}

  // public initChild(
  //   _zoneName: string,
  //   _dnskeyMessage: Message,
  //   _dsMessage: Message,
  //   _referenceDate: Date,
  // ): VerificationResult<Zone> {
  //   throw new Error('asd');
  // }

  public verifyRrset(rrset: SignedRRSet, referenceDate: Date): boolean {
    return rrset.verify(this.dnskeys, referenceDate);
  }
}
