import { RRSet } from '../dns/RRSet';
import { Record } from '../dns/Record';
import { DnskeyRecord, RrsigRecord } from '../dnssecRecords';
import { DnssecRecordType } from '../DnssecRecordType';
import { RrsigData } from '../rdata/RrsigData';
import { Question } from '../dns/Question';
import { DatePeriod } from './DatePeriod';
import { DnskeyData } from '../rdata/DnskeyData';
import { isChildZone } from '../dns/name';

/**
 * RRSet with one or more corresponding RRSigs.
 */
export class SignedRRSet {
  static initFromRecords(question: Question, records: readonly Record[]): SignedRRSet {
    const rrsetRecords = records.filter((r) => r.typeId !== DnssecRecordType.RRSIG);
    const rrset = RRSet.init(question, rrsetRecords);

    const rrsigRecords = records
      .filter(
        (r) =>
          r.typeId === DnssecRecordType.RRSIG && r.name === rrset.name && r.class_ === rrset.class_,
      )
      .reduce(function deserialise(acc, record): readonly RrsigRecord[] {
        const data = RrsigData.initFromPacket(record.dataFields);
        if (data.signerName !== rrset.name && !isChildZone(data.signerName, rrset.name)) {
          // Signer is off tree
          return acc;
        }
        return [...acc, { record, data }];
      }, [] as readonly RrsigRecord[]);

    return new SignedRRSet(rrset, rrsigRecords);
  }

  protected constructor(
    public readonly rrset: RRSet,
    public readonly rrsigs: readonly RrsigRecord[],
  ) {}

  get signerNames(): readonly string[] {
    const names = this.rrsigs.map((s) => s.data.signerName);
    const uniqueNames = new Set(names);
    return [...uniqueNames];
  }

  public verify(
    dnsKeys: readonly DnskeyRecord[],
    datePeriod: DatePeriod,
    expectedSigner?: string,
  ): boolean {
    const validRrsigs = this.rrsigs.reduce((acc, rrsig) => {
      const matchingDnskeys = dnsKeys.filter(
        (dnskey) =>
          dnskey.data.verifyRrsig(rrsig.data, datePeriod) &&
          (expectedSigner ?? dnskey.record.name) === rrsig.data.signerName,
      );
      const additionalItems = matchingDnskeys.map((dnskey) => ({
        dnskey: dnskey.data,
        rrsig: rrsig.data,
      }));
      return [...acc, ...additionalItems];
    }, [] as readonly { readonly rrsig: RrsigData; readonly dnskey: DnskeyData }[]);

    return validRrsigs.some(({ dnskey, rrsig }) => rrsig.verifyRrset(this.rrset, dnskey.publicKey));
  }
}
