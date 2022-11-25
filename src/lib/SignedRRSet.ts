import { RRSet } from './dns/RRSet';
import type { DnsRecord } from './dns/DnsRecord';
import type { DnskeyRecord, RrsigRecord } from './dnssecRecords';
import { DnssecRecordType } from './DnssecRecordType';
import { RrsigData } from './rdata/RrsigData';
import type { Question } from './dns/Question';
import type { DatePeriod } from './DatePeriod';
import type { DnskeyData } from './rdata/DnskeyData';
import { isChildZone } from './dns/name';

/**
 * RRSet with one or more corresponding RRSigs.
 */
export class SignedRRSet {
  static initFromRecords(question: Question, records: readonly DnsRecord[]): SignedRRSet {
    const rrsetRecords = records.filter((r) => r.typeId !== DnssecRecordType.RRSIG);
    const rrset = RRSet.init(question, rrsetRecords);

    const rrsigRecords = records
      .filter(
        (r) =>
          r.typeId === DnssecRecordType.RRSIG &&
          r.name === rrset.name &&
          r.classId === rrset.classId,
      )
      .reduce<readonly RrsigRecord[]>(function deserialise(
        accumulator,
        record,
      ): readonly RrsigRecord[] {
        const data = RrsigData.initFromPacket(record.dataFields);
        if (data.signerName !== rrset.name && !isChildZone(data.signerName, rrset.name)) {
          // Signer is off tree
          return accumulator;
        }
        return [...accumulator, { record, data }];
      },
      []);

    return new SignedRRSet(rrset, rrsigRecords);
  }

  protected constructor(
    public readonly rrset: RRSet,
    public readonly rrsigs: readonly RrsigRecord[],
  ) {}

  get signerNames(): readonly string[] {
    const names = this.rrsigs.map((s) => s.data.signerName);
    const uniqueNames = new Set(names);
    return Array.from(uniqueNames).sort((a, b) => b.length - a.length);
  }

  public verify(
    dnsKeys: readonly DnskeyRecord[],
    datePeriod: DatePeriod,
    expectedSigner?: string,
  ): boolean {
    const validRrsigs = this.rrsigs.reduce<
      readonly { readonly rrsig: RrsigData; readonly dnskey: DnskeyData }[]
    >((accumulator, rrsig) => {
      const matchingDnskeys = dnsKeys.filter(
        (dnskey) =>
          dnskey.data.verifyRrsig(rrsig.data, datePeriod) &&
          (expectedSigner ?? dnskey.record.name) === rrsig.data.signerName,
      );
      const additionalItems = matchingDnskeys.map((dnskey) => ({
        dnskey: dnskey.data,
        rrsig: rrsig.data,
      }));
      return [...accumulator, ...additionalItems];
    }, []);

    return validRrsigs.some(({ dnskey, rrsig }) => rrsig.verifyRrset(this.rrset, dnskey.publicKey));
  }
}
