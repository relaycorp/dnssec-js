import { RRSet } from '../dns/RRSet';
import { Record } from '../dns/Record';
import { RrsigRecord } from '../dnssecRecords';
import { DnssecValidationError } from '../errors';
import { DnssecRecordType } from '../DnssecRecordType';
import { RrsigData } from '../rdata/RrsigData';

/**
 * RRSet with one or more corresponding RRSigs.
 */
export class SignedRRSet {
  static initFromRecords(records: readonly Record[]): SignedRRSet {
    const rrsetRecords = records.filter((r) => r.type !== DnssecRecordType.RRSIG);
    if (rrsetRecords.length === 0) {
      throw new DnssecValidationError('RRset cannot be empty');
    }
    const rrset = new RRSet(rrsetRecords);

    const rrsigRecords = records
      .filter((r) => r.type === DnssecRecordType.RRSIG)
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
      })
      .filter(
        (r) =>
          r.record.name === rrset.name &&
          r.record.class_ === rrset.class_ &&
          r.data.type === rrset.type &&
          r.data.ttl === rrset.ttl,
      );

    return new SignedRRSet(rrset, rrsigRecords);
  }

  protected constructor(
    public readonly rrset: RRSet,
    public readonly rrsigs: readonly RrsigRecord[],
  ) {}
}
