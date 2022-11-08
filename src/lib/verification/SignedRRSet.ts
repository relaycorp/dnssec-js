import { RRSet } from '../dns/RRSet';
import { Record } from '../dns/Record';
import { DnskeyRecord, RrsigRecord } from '../dnssecRecords';
import { DnssecValidationError } from '../errors';
import { DnssecRecordType } from '../DnssecRecordType';
import { RrsigData } from '../rdata/RrsigData';
import { Question } from '../dns/Question';

/**
 * RRSet with one or more corresponding RRSigs.
 */
export class SignedRRSet {
  static initFromRecords(question: Question, records: readonly Record[]): SignedRRSet {
    const rrsetRecords = records.filter((r) => r.type !== DnssecRecordType.RRSIG);
    const rrset = RRSet.init(question, rrsetRecords);

    const rrsigRecords = records
      .filter(
        (r) =>
          r.type === DnssecRecordType.RRSIG && r.name === rrset.name && r.class_ === rrset.class_,
      )
      .map(function (record): RrsigRecord {
        let data: RrsigData;
        try {
          data = RrsigData.deserialise(record.dataSerialised);
        } catch (err) {
          throw new DnssecValidationError(
            `RRSig data for ${record.name}/${record.type} is malformed`,
          );
        }
        return { record, data };
      });

    return new SignedRRSet(rrset, rrsigRecords);
  }

  protected constructor(
    public readonly rrset: RRSet,
    public readonly rrsigs: readonly RrsigRecord[],
  ) {}

  public verify(dnsKeys: readonly DnskeyRecord[], referenceDate: Date): boolean {
    const validRrsigs = this.rrsigs.filter((rrsig) =>
      dnsKeys.some(
        (dnskey) =>
          dnskey.data.verifyRrsig(rrsig.data, referenceDate) &&
          dnskey.record.name === rrsig.record.name,
      ),
    );
    return validRrsigs.some((rrsig) => rrsig.data.verifyRrset(this.rrset));
  }
}
