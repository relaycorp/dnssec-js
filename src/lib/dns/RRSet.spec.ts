import { RRSet } from './RRSet';
import {
  RECORD,
  RECORD_DATA,
  RECORD_NAME,
  RECORD_TTL,
  RECORD_TYPE_ID,
} from '../../testUtils/stubs';
import { RRSetError } from '../errors';
import { Record } from './Record';
import { DNSClass } from './DNSClass';

describe('RRSet', () => {
  describe('constructor', () => {
    test('At least one record should be specified', () => {
      expect(() => new RRSet([])).toThrowWithMessage(
        RRSetError,
        'At least one record should be specified',
      );
    });

    test('All record names should match', () => {
      const record2 = new Record(
        `sub.${RECORD_NAME}`,
        RECORD_TYPE_ID,
        DNSClass.IN,
        RECORD_TTL,
        RECORD_DATA,
      );

      expect(() => new RRSet([RECORD, record2])).toThrowWithMessage(
        RRSetError,
        `Record names don't match (${RECORD.name}, ${record2.name})`,
      );
    });

    test('All record classes should match', () => {
      const record2 = new Record(
        RECORD_NAME,
        RECORD_TYPE_ID,
        DNSClass.IN + 1,
        RECORD_TTL,
        RECORD_DATA,
      );

      expect(() => new RRSet([RECORD, record2])).toThrowWithMessage(
        RRSetError,
        `Record classes don't match (${RECORD.class_}, ${record2.class_})`,
      );
    });

    test('All record types should match', () => {
      const record2 = new Record(
        RECORD_NAME,
        RECORD_TYPE_ID + 1,
        DNSClass.IN,
        RECORD_TTL,
        RECORD_DATA,
      );

      expect(() => new RRSet([RECORD, record2])).toThrowWithMessage(
        RRSetError,
        `Record types don't match (${RECORD.type}, ${record2.type})`,
      );
    });

    test('All record TTls should match', () => {
      const record2 = new Record(
        RECORD_NAME,
        RECORD_TYPE_ID,
        DNSClass.IN,
        RECORD_TTL + 1,
        RECORD_DATA,
      );

      expect(() => new RRSet([RECORD, record2])).toThrowWithMessage(
        RRSetError,
        `Record TTLs don't match (${RECORD.ttl}, ${record2.ttl})`,
      );
    });

    test('Name property should be set', () => {
      const rrset = new RRSet([RECORD]);

      expect(rrset.name).toEqual(RECORD.name);
    });

    test('Class property should be set', () => {
      const rrset = new RRSet([RECORD]);

      expect(rrset.class_).toEqual(RECORD.class_);
    });

    test('Type property should be set', () => {
      const rrset = new RRSet([RECORD]);

      expect(rrset.type).toEqual(RECORD.type);
    });

    test('TTL property should be set', () => {
      const rrset = new RRSet([RECORD]);

      expect(rrset.ttl).toEqual(RECORD.ttl);
    });
  });
});
