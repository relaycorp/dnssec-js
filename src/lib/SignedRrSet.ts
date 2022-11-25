import type { RRSigData } from '@leichtgewicht/dns-packet';

import { RrSet } from './dns/RrSet';
import type { DnsRecord } from './dns/DnsRecord';
import type { DnskeyRecord, RrsigRecord } from './dnssecRecords';
import { DnssecRecordType } from './DnssecRecordType';
import { RrsigData } from './rdata/RrsigData';
import type { Question } from './dns/Question';
import type { DatePeriod } from './DatePeriod';
import type { DnskeyData } from './rdata/DnskeyData';
import { isChildZone } from './dns/name';

/**
 * RRset with one or more corresponding RRSigs.
 */
export class SignedRrSet {
  public static initFromRecords(question: Question, records: readonly DnsRecord[]): SignedRrSet {
    const rrsetRecords = records.filter((record) => record.typeId !== DnssecRecordType.RRSIG);
    const rrset = RrSet.init(question, rrsetRecords);

    const rrsigRecords = records
      .filter(
        (record) =>
          record.typeId === DnssecRecordType.RRSIG &&
          record.name === rrset.name &&
          record.classId === rrset.classId,
      )
      .reduce<readonly RrsigRecord[]>(function deserialise(
        accumulator,
        record,
      ): readonly RrsigRecord[] {
        const data = RrsigData.initFromPacket(record.dataFields as RRSigData);
        if (data.signerName !== rrset.name && !isChildZone(data.signerName, rrset.name)) {
          // Signer is off tree
          return accumulator;
        }
        return [...accumulator, { record, data }];
      },
      []);

    return new SignedRrSet(rrset, rrsigRecords);
  }

  protected constructor(
    public readonly rrset: RrSet,
    public readonly rrsigs: readonly RrsigRecord[],
  ) {}

  public get signerNames(): readonly string[] {
    const names = this.rrsigs.map((record) => record.data.signerName);
    const uniqueNames = new Set(names);
    return Array.from(uniqueNames).sort((name1, name2) => name2.length - name1.length);
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
