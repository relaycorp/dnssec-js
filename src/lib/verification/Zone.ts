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

export class Zone {
  // public static init(_dnskeyMessage: Message, _dsMessage: Message): VerificationResult<Zone> {
  //   throw new Error('implement');
  // }

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

    let parsedDnskeys: readonly DnskeyRecord[];
    try {
      parsedDnskeys = dnskeySignedRrset.rrset.records.map((record) => ({
        data: DnskeyData.deserialise(record.dataSerialised),
        record,
      }));
    } catch (_) {
      return { status: SecurityStatus.BOGUS, reasonChain: ['Found malformed DNSKEY'] };
    }
    const zskDnskeys = parsedDnskeys.filter((k) => dsData.some((ds) => ds.verifyDnskey(k)));

    if (zskDnskeys.length === 0) {
      return { status: SecurityStatus.BOGUS, reasonChain: ['No DNSKEY matched specified DS(s)'] };
    }

    if (!dnskeySignedRrset.verify(zskDnskeys, referenceDate)) {
      return { status: SecurityStatus.BOGUS, reasonChain: ['No valid RRSig was found'] };
    }

    return {
      status: SecurityStatus.SECURE,
      result: new Zone(
        zoneName,
        parsedDnskeys.map((r) => r.data),
      ),
    };
  }

  protected constructor(
    public readonly name: string,
    public readonly dnskeys: readonly DnskeyData[],
  ) {}

  // public verifyRrset(_rrset: SignedRRSet): SecurityStatus {
  //   throw new Error('asd');
  // }

  // public verifyChildZone(_child: Zone): SecurityStatus {
  //   throw new Error('asd');
  // }
}
