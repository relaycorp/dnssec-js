import { RRSet } from './RRSet';
import { ANSWER } from '../testUtils/stubs';
import { SignedRRSetError } from './errors';

describe('RRSet', () => {
  describe('constructor', () => {
    test('At least one record should be specified', () => {
      expect(() => new RRSet([])).toThrowWithMessage(
        SignedRRSetError,
        'At least one record should be specified',
      );
    });

    test('All record names should match', () => {
      const record1 = { ...ANSWER };
      const record2 = { ...record1, name: `sub.${record1.name}` };

      expect(() => new RRSet([record1, record2])).toThrowWithMessage(
        SignedRRSetError,
        `Record names don't match (${record1.name}, ${record2.name})`,
      );
    });

    test('All record classes should match', () => {
      const record1 = { ...ANSWER };
      const record2 = { ...record1, class: record1.class + 1 };

      expect(() => new RRSet([record1, record2])).toThrowWithMessage(
        SignedRRSetError,
        `Record classes don't match (${record1.class}, ${record2.class})`,
      );
    });

    test('All record types should match', () => {
      const record1 = { ...ANSWER };
      const record2 = { ...record1, type: record1.type + 1 };

      expect(() => new RRSet([record1, record2])).toThrowWithMessage(
        SignedRRSetError,
        `Record types don't match (${record1.type}, ${record2.type})`,
      );
    });

    test('Name property should be set', () => {
      const rrset = new RRSet([ANSWER]);

      expect(rrset.name).toEqual(ANSWER.name);
    });

    test('Class property should be set', () => {
      const rrset = new RRSet([ANSWER]);

      expect(rrset.class_).toEqual(ANSWER.class);
    });

    test('Type property should be set', () => {
      const rrset = new RRSet([ANSWER]);

      expect(rrset.type).toEqual(ANSWER.type);
    });
  });
});
