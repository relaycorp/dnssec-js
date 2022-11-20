import { RRSet } from './RRSet';
import { QUESTION, RECORD, RRSET } from '../../testUtils/dnsStubs';
import { DnsClass } from './ianaClasses';
import { DnsError } from './DnsError';
import { IANA_RR_TYPE_IDS } from './ianaRrTypes';

describe('RRSet', () => {
  describe('init', () => {
    test('RRset should be empty if there are no matching records', () => {
      const nonMatchingRecord = RECORD.shallowCopy({ name: `not-${RECORD.name}` });

      expect(() => RRSet.init(QUESTION, [nonMatchingRecord])).toThrowWithMessage(
        DnsError,
        `RRset for ${QUESTION.key} should have at least one matching record`,
      );
    });

    test('Record names should match', () => {
      const record2 = RECORD.shallowCopy({ name: `not-${RECORD.name}` });

      const rrset = RRSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toEqual([RECORD]);
    });

    test('Record classes should match', () => {
      const record2 = RECORD.shallowCopy({ class: DnsClass.IN + 1 });

      const rrset = RRSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toEqual([RECORD]);
    });

    test('Record types should match', () => {
      const type = IANA_RR_TYPE_IDS.A;
      expect(type).not.toEqual(RECORD.typeId);
      const record2 = RECORD.shallowCopy({ type });

      const rrset = RRSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toEqual([RECORD]);
    });

    test('Record TTLs should match', () => {
      const record2 = RECORD.shallowCopy({ ttl: RECORD.ttl + 1 });

      expect(() => RRSet.init(QUESTION, [RECORD, record2])).toThrowWithMessage(
        DnsError,
        `RRset for ${QUESTION.key} contains different TTLs ` +
          `(e.g., ${RECORD.ttl}, ${record2.ttl})`,
      );
    });

    test('Multiple records should be supported', () => {
      const record2 = RECORD.shallowCopy({ dataSerialised: Buffer.from([1, 2]) });

      const rrset = RRSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toContainAllValues([RECORD, record2]);
    });

    test('Name property should be set', () => {
      expect(RRSET.name).toEqual(RECORD.name);
    });

    test('Class property should be set', () => {
      expect(RRSET.class_).toEqual(RECORD.class_);
    });

    test('Type property should be set', () => {
      expect(RRSET.type).toEqual(RECORD.typeId);
    });

    test('TTL property should be set', () => {
      expect(RRSET.ttl).toEqual(RECORD.ttl);
    });

    describe('Ordering', () => {
      test('Smaller RDATA should come first', () => {
        const longer = RECORD.shallowCopy({ dataSerialised: Buffer.from([2, 0, 1]) });
        const shorter = RECORD.shallowCopy({ dataSerialised: Buffer.from([1, 255]) });

        const rrset = RRSet.init(QUESTION, [longer, shorter]);

        expect(rrset.records).toEqual([shorter, longer]);
      });

      test('RDATA should be sorted from the left if they have same length', () => {
        const record1 = RECORD.shallowCopy({ dataSerialised: Buffer.from([1, 0]) });
        const record2 = RECORD.shallowCopy({ dataSerialised: Buffer.from([1, 1]) });

        const rrset = RRSet.init(QUESTION, [record2, record1]);

        expect(rrset.records).toEqual([record1, record2]);
      });

      test('Duplicated records should be deleted', () => {
        const record1 = RECORD.shallowCopy({});
        const record2 = RECORD.shallowCopy({});

        const rrset = RRSet.init(QUESTION, [record1, record2]);

        expect(rrset.records).toEqual([record1]);
      });
    });
  });
});
