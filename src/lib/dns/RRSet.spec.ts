import { RRSet } from './RRSet';
import { QUESTION, RECORD } from '../../testUtils/dnsStubs';
import { RRSetError } from '../errors';
import { DNSClass } from './DNSClass';

describe('RRSet', () => {
  describe('init', () => {
    test('RRset should be empty if there are no matching records', () => {
      const nonMatchingRecord = RECORD.shallowCopy({ name: `not-${RECORD.name}` });

      expect(() => RRSet.init(QUESTION, [nonMatchingRecord])).toThrowWithMessage(
        RRSetError,
        'At least one matching record should be specified',
      );
    });

    test('Record names should match', () => {
      const record2 = RECORD.shallowCopy({ name: `not-${RECORD.name}` });

      const rrset = RRSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toEqual([RECORD]);
    });

    test('Record classes should match', () => {
      const record2 = RECORD.shallowCopy({ class: DNSClass.IN + 1 });

      const rrset = RRSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toEqual([RECORD]);
    });

    test('Record types should match', () => {
      const record2 = RECORD.shallowCopy({ type: RECORD.type + 1 });

      const rrset = RRSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toEqual([RECORD]);
    });

    test('Record TTLs should match', () => {
      const record2 = RECORD.shallowCopy({ ttl: RECORD.ttl + 1 });

      expect(() => RRSet.init(QUESTION, [RECORD, record2])).toThrowWithMessage(
        RRSetError,
        `Record TTLs don't match (${RECORD.ttl}, ${record2.ttl})`,
      );
    });

    test('Multiple records should be supported', () => {
      const record2 = RECORD.shallowCopy({ dataSerialised: Buffer.allocUnsafe(1) });

      const rrset = RRSet.init(QUESTION, [RECORD, record2]);

      expect(rrset.records).toEqual([RECORD, record2]);
    });

    test('Name property should be set', () => {
      const rrset = RRSet.init(QUESTION, [RECORD]);

      expect(rrset.name).toEqual(RECORD.name);
    });

    test('Class property should be set', () => {
      const rrset = RRSet.init(QUESTION, [RECORD]);

      expect(rrset.class_).toEqual(RECORD.class_);
    });

    test('Type property should be set', () => {
      const rrset = RRSet.init(QUESTION, [RECORD]);

      expect(rrset.type).toEqual(RECORD.type);
    });

    test('TTL property should be set', () => {
      const rrset = RRSet.init(QUESTION, [RECORD]);

      expect(rrset.ttl).toEqual(RECORD.ttl);
    });
  });
});
