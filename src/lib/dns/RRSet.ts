import { Record } from './Record';
import { RRSetError } from '../errors';
import { DNSClass } from './DNSClass';
import { Question } from './Question';

/**
 * A set of Resource Records (aka `RRset`).
 */
export class RRSet {
  /**
   * Return the RRset for the subset of `records` that match the `question`.
   *
   * @param question
   * @param records
   */
  public static init(question: Question, records: readonly Record[]): RRSet {
    const matchingRecords = records.filter(
      (r) => r.name === question.name && r.class_ === question.class && r.type === question.type,
    );

    if (matchingRecords.length === 0) {
      throw new RRSetError('At least one matching record should be specified');
    }

    const ttl = records[0].ttl;
    const mismatchingTtlRecord = matchingRecords.find((r) => r.ttl !== ttl);
    if (mismatchingTtlRecord) {
      throw new RRSetError(`Record TTLs don't match (${ttl}, ${mismatchingTtlRecord.ttl})`);
    }

    return new RRSet(question.name, question.class, question.type, ttl, matchingRecords);
  }

  protected constructor(
    public readonly name: string,
    public readonly class_: DNSClass,
    public readonly type: number,
    public readonly ttl: number,
    public readonly records: readonly Record[],
  ) {}
}
