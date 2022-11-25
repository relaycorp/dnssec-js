import { QUESTION, RECORD, RRSET } from '../../testUtils/dnsStubs';

import { RrSet } from './RrSet';
import { DnsClass } from './ianaClasses';
import { DnsError } from './DnsError';
import { IANA_RR_TYPE_IDS } from './ianaRrTypes';

describe('RrSet', () => {
  describe('init', () => {
    test('RRset should be empty if there are no matching records', () => {
      const nonMatchingRecord = RECORD.shallowCopy({ name: `not-${RECORD.name}` });

      expect(() => RrSet.init(QUESTION, [nonMatchingRecord])).toThrowWithMessage(
        DnsError,
        `RRset for ${QUESTION.key} should have at least one matching record`,
      );
    });

    test('Record names should match', () => {
      const record2 = RECORD.shallowCopy({ name: `not-${RECORD.name}` });

      const rrset = RrSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toStrictEqual([RECORD]);
    });

    test('Record classes should match', () => {
      const record2 = RECORD.shallowCopy({ class: DnsClass.IN + 1 });

      const rrset = RrSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toStrictEqual([RECORD]);
    });

    test('Record types should match', () => {
      const type = IANA_RR_TYPE_IDS.A;
      expect(type).not.toStrictEqual(RECORD.typeId);
      const record2 = RECORD.shallowCopy({ type });

      const rrset = RrSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toStrictEqual([RECORD]);
    });

    test('Record TTLs should match', () => {
      const record2 = RECORD.shallowCopy({ ttl: RECORD.ttl + 1 });

      expect(() => RrSet.init(QUESTION, [RECORD, record2])).toThrowWithMessage(
        DnsError,
        `RRset for ${QUESTION.key} contains different TTLs ` +
          `(e.g., ${RECORD.ttl}, ${record2.ttl})`,
      );
    });

    test('Multiple records should be supported', () => {
      const record2 = RECORD.shallowCopy({ dataSerialised: Buffer.from([1, 2]) });

      const rrset = RrSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toContainAllValues([RECORD, record2]);
    });

    test('Name property should be set', () => {
      expect(RRSET.name).toStrictEqual(RECORD.name);
    });

    test('Class property should be set', () => {
      expect(RRSET.classId).toStrictEqual(RECORD.classId);
    });

    test('Type property should be set', () => {
      expect(RRSET.type).toStrictEqual(RECORD.typeId);
    });

    test('TTL property should be set', () => {
      expect(RRSET.ttl).toStrictEqual(RECORD.ttl);
    });

    describe('Ordering', () => {
      test('Absence of an octet should sort before a zero octet', () => {
        const longer = RECORD.shallowCopy({});
        const shorter = RECORD.shallowCopy({});

        // @ts-expect-error We can't initialise a malformed record, so we have to mutate it
        longer.dataSerialised = Buffer.from([1, 0]);

        // @ts-expect-error We can't initialise a malformed record, so we have to mutate it
        shorter.dataSerialised = Buffer.from([1]);

        expect(RrSet.init(QUESTION, [longer, shorter]).records).toStrictEqual([shorter, longer]);
        expect(RrSet.init(QUESTION, [shorter, longer]).records).toStrictEqual([shorter, longer]);
      });

      test('RDATA should be sorted from the left if they have same length', () => {
        const record1 = RECORD.shallowCopy({ dataSerialised: Buffer.from([1, 0]) });
        const record2 = RECORD.shallowCopy({ dataSerialised: Buffer.from([1, 1]) });

        const rrset = RrSet.init(QUESTION, [record2, record1]);

        expect(rrset.records).toStrictEqual([record1, record2]);
      });

      test('Duplicated records should be deleted', () => {
        const record1 = RECORD.shallowCopy({});
        const record2 = RECORD.shallowCopy({});

        const rrset = RrSet.init(QUESTION, [record1, record2]);

        expect(rrset.records).toStrictEqual([record1]);
      });
    });
  });
});
