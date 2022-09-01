const dnspacket = await import('dns-packet');

import { Record } from './Record.js';
import {
  RECORD_CLASS,
  RECORD_DATA,
  RECORD_NAME,
  RECORD_TTL,
  RECORD_TYPE,
  RECORD_TYPE_ID,
} from '../testUtils/stubs.js';

export {};

describe('Record', () => {
  describe('serialise', () => {
    const record = new Record(RECORD_NAME, RECORD_TYPE_ID, RECORD_CLASS, RECORD_TTL, RECORD_DATA);

    test('Name should be serialised', () => {
      const serialisation = record.serialise();

      expect(dnspacket.a.decode(serialisation)).toHaveProperty('name', record.name);
    });

    test('Type should be serialised', () => {
      const serialisation = record.serialise();

      expect(dnspacket.a.decode(serialisation)).toHaveProperty('type', RECORD_TYPE);
    });

    test.todo('Class should be serialised');

    test.todo('TTL should be serialised');

    test.todo('Data should be serialised');
  });
});
