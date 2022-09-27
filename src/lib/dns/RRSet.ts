import { Record } from './Record';
import { RRSetError } from '../errors';
import { DNSClass } from './DNSClass';
import { RecordType } from './RecordType';

/**
 * A set of Resource Records (aka `RRset`).
 */
export class RRSet {
  public readonly name: string;
  public readonly class_: DNSClass;
  public readonly type: RecordType;
  public readonly ttl: number;

  constructor(public readonly records: readonly Record[]) {
    if (records.length === 0) {
      throw new RRSetError('At least one record should be specified');
    }

    const [firstRecord, ...remainingRecords] = records;

    for (const record of remainingRecords) {
      if (record.name !== firstRecord.name) {
        throw new RRSetError(`Record names don't match (${firstRecord.name}, ${record.name})`);
      }
      if (record.class_ !== firstRecord.class_) {
        throw new RRSetError(
          `Record classes don't match (${firstRecord.class_}, ${record.class_})`,
        );
      }
      if (record.type !== firstRecord.type) {
        throw new RRSetError(`Record types don't match (${firstRecord.type}, ${record.type})`);
      }
      if (record.ttl !== firstRecord.ttl) {
        throw new RRSetError(`Record TTLs don't match (${firstRecord.ttl}, ${record.ttl})`);
      }
    }

    this.name = firstRecord.name;
    this.type = firstRecord.type;
    this.class_ = firstRecord.class_;
    this.ttl = firstRecord.ttl;
  }
}
