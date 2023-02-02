import type { RRSigData } from '@leichtgewicht/dns-packet';

import { RrSet } from './utils/dns/RrSet.js';
import type { DnsRecord } from './utils/dns/DnsRecord.js';
import type { DnskeyRecord, RrsigRecord } from './records/dnssecRecords.js';
import { DnssecRecordType } from './records/DnssecRecordType.js';
import { RrsigData } from './records/RrsigData.js';
import type { Question } from './utils/dns/Question.js';
import { DatePeriod } from './DatePeriod.js';
import { isChildZone } from './utils/dns/name.js';
import { type DatedValue } from './DatedValue.js';

interface RrsigWithDnskeyData {
  readonly rrsig: RrsigRecord;
  readonly dnskey: DatedValue<DnskeyRecord>;
}

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

  protected filterRrsigs(
    dnsKeys: readonly DatedValue<DnskeyRecord>[],
    expectedSigner: string | undefined,
  ) {
    return this.rrsigs.reduce<readonly RrsigWithDnskeyData[]>((accumulator, rrsig) => {
      const matchingDnskeys = dnsKeys.filter(
        (dnskey) =>
          dnskey.value.data.verifyRrsig(rrsig.data, dnskey.datePeriods) &&
          (expectedSigner ?? dnskey.value.record.name) === rrsig.data.signerName,
      );
      const additionalItems = matchingDnskeys.map((dnskey) => ({
        dnskey,
        rrsig,
      }));
      return [...accumulator, ...additionalItems];
    }, []);
  }

  public verify(
    dnsKeys: readonly DatedValue<DnskeyRecord>[],
    expectedSigner?: string,
  ): readonly DatePeriod[] {
    const eligibleRrsigs = this.filterRrsigs(dnsKeys, expectedSigner);

    const matchingRrsigs = eligibleRrsigs.filter(({ dnskey, rrsig }) =>
      rrsig.data.verifyRrset(this.rrset, dnskey.value.data.publicKey),
    );

    return matchingRrsigs
      .flatMap(({ dnskey, rrsig }) =>
        dnskey.datePeriods.map((period) =>
          period.intersect(
            DatePeriod.init(rrsig.data.signatureInception, rrsig.data.signatureExpiry),
          ),
        ),
      )
      .filter((period) => period !== undefined) as DatePeriod[];
  }
}
