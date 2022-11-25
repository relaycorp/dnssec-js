import type { DnsRecord } from './DnsRecord';
import type { DnsClass } from './ianaClasses';
import type { Question } from './Question';
import { DnsError } from './DnsError';

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
  public static init(question: Question, records: readonly DnsRecord[]): RRSet {
    const matchingRecords = records.filter(
      (r) =>
        r.name === question.name && r.class_ === question.class_ && r.typeId === question.typeId,
    );

    if (matchingRecords.length === 0) {
      throw new DnsError(`RRset for ${question.key} should have at least one matching record`);
    }

    const [firstRecord, ...remainingRecords] = records;
    const { ttl } = firstRecord;
    const mismatchingTtlRecord = remainingRecords.find((r) => r.ttl !== ttl);
    if (mismatchingTtlRecord) {
      throw new DnsError(
        `RRset for ${question.key} contains different TTLs ` +
          `(e.g., ${ttl}, ${mismatchingTtlRecord.ttl})`,
      );
    }

    return new RRSet(
      question.name,
      question.class_,
      question.typeId,
      ttl,
      canonicallySortRecords(matchingRecords),
    );
  }

  protected constructor(
    public readonly name: string,
    public readonly class_: DnsClass,
    public readonly type: number,
    public readonly ttl: number,
    public readonly records: readonly DnsRecord[],
  ) {}
}

/**
 * Sort records per RFC 4034 (Section 6.3).
 *
 * @param originalRecords
 * @link https://www.rfc-editor.org/rfc/rfc4034#section-6.3
 */
function canonicallySortRecords(originalRecords: readonly DnsRecord[]): readonly DnsRecord[] {
  const recordSorted = Array.from(originalRecords).sort((a, b) => {
    const maxLength = Math.max(a.dataSerialised.byteLength, b.dataSerialised.byteLength);
    for (let index = 0; index < maxLength; index++) {
      const aOctet = a.dataSerialised[index];
      if (aOctet === undefined) {
        return -1;
      }

      const bOctet = b.dataSerialised[index];
      if (bOctet === undefined) {
        return 1;
      }

      if (aOctet !== bOctet) {
        return aOctet - bOctet;
      }
    }

    return 0;
  });

  return recordSorted.reduce<readonly DnsRecord[]>((accumulator, record) => {
    const previousRecord = accumulator[accumulator.length - 1];
    const isDuplicated =
      previousRecord && record.dataSerialised.equals(previousRecord.dataSerialised);
    return isDuplicated ? accumulator : [...accumulator, record];
  }, []);
}
