import type { DnsRecord } from './DnsRecord';
import type { DnsClass } from './ianaClasses';
import type { Question } from './Question';
import { DnsError } from './DnsError';

/**
 * Sort records per RFC 4034 (Section 6.3).
 *
 * See https://www.rfc-editor.org/rfc/rfc4034#section-6.3
 */
function canonicallySortRecords(originalRecords: readonly DnsRecord[]): readonly DnsRecord[] {
  // eslint-disable-next-line max-statements
  const recordSorted = Array.from(originalRecords).sort((recordA, recordB) => {
    const maxLength = Math.max(
      recordA.dataSerialised.byteLength,
      recordB.dataSerialised.byteLength,
    );
    for (let index = 0; index < maxLength; index++) {
      if (recordA.dataSerialised.byteLength < index + 1) {
        // eslint-disable-next-line @typescript-eslint/no-magic-numbers
        return -1;
      }

      if (recordB.dataSerialised.byteLength < index + 1) {
        return 1;
      }

      const aOctet = recordA.dataSerialised[index];
      const bOctet = recordB.dataSerialised[index];
      if (aOctet !== bOctet) {
        return aOctet - bOctet;
      }
    }

    return 0;
  });

  return recordSorted.reduce<readonly DnsRecord[]>((accumulator, record) => {
    const previousRecord = accumulator.length === 0 ? null : accumulator[accumulator.length - 1];
    const isDuplicated = previousRecord?.dataSerialised.equals(record.dataSerialised) ?? false;
    return isDuplicated ? accumulator : [...accumulator, record];
  }, []);
}

/**
 * A set of Resource Records (aka `RRset`).
 */
export class RrSet {
  /**
   * Return the RRset for the subset of `records` that match the `question`.
   */
  public static init(question: Question, records: readonly DnsRecord[]): RrSet {
    const matchingRecords = records.filter(
      (record) =>
        record.name === question.name &&
        record.classId === question.classId &&
        record.typeId === question.typeId,
    );

    if (matchingRecords.length === 0) {
      throw new DnsError(`RRset for ${question.key} should have at least one matching record`);
    }

    const [firstRecord, ...remainingRecords] = records;
    const { ttl } = firstRecord;
    const mismatchingTtlRecord = remainingRecords.find((record) => record.ttl !== ttl);
    if (mismatchingTtlRecord) {
      throw new DnsError(
        `RRset for ${question.key} contains different TTLs ` +
          `(e.g., ${ttl}, ${mismatchingTtlRecord.ttl})`,
      );
    }

    return new RrSet(
      question.name,
      question.classId,
      question.typeId,
      ttl,
      canonicallySortRecords(matchingRecords),
    );
  }

  protected constructor(
    public readonly name: string,
    public readonly classId: DnsClass,
    public readonly type: number,
    public readonly ttl: number,
    public readonly records: readonly DnsRecord[],
  ) {}
}
