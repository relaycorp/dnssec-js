import { answer as ANSWER, TxtAnswer } from '@leichtgewicht/dns-packet';

import { RECORD, RECORD_CLASS_STR, RECORD_DATA_TXT_DATA, RECORD_TYPE } from '../../testUtils/stubs';

describe('Record', () => {
  describe('serialise', () => {
    const recordNameWithoutDot = RECORD.name.replace(/\.$/, '');

    test('Record name should be serialised', () => {
      const serialisation = RECORD.serialise();

      expect(ANSWER.decode(serialisation)).toHaveProperty('name', recordNameWithoutDot);
    });

    test('Record type should be serialised', () => {
      const serialisation = RECORD.serialise();

      expect(ANSWER.decode(serialisation)).toHaveProperty('type', RECORD_TYPE);
    });

    test('Record class should be serialised', () => {
      const serialisation = RECORD.serialise();

      expect(ANSWER.decode(serialisation)).toHaveProperty('class', RECORD_CLASS_STR);
    });

    test('Record TTL should be serialised', () => {
      const serialisation = RECORD.serialise();

      expect(ANSWER.decode(serialisation)).toHaveProperty('ttl', RECORD.ttl);
    });

    test('Record data should be serialised', () => {
      const serialisation = RECORD.serialise();

      const record = ANSWER.decode(serialisation) as TxtAnswer;
      expect(record.data).toHaveLength(1);
      expect(RECORD_DATA_TXT_DATA.equals((record as any).data[0])).toBeTrue();
    });
  });
});
