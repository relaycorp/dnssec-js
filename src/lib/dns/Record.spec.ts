import { answer as ANSWER, TxtAnswer } from '@leichtgewicht/dns-packet';

import {
  RECORD,
  RECORD_CLASS_STR,
  RECORD_DATA_TXT_DATA,
  RECORD_TYPE_STR,
} from '../../testUtils/dnsStubs';

describe('Record', () => {
  describe('question', () => {
    test('Name should be set', () => {
      const question = RECORD.makeQuestion();

      expect(question.name).toEqual(RECORD.name);
    });

    test('Type should be set', () => {
      const question = RECORD.makeQuestion();

      expect(question.typeId).toEqual(RECORD.type);
    });

    test('Class should be set', () => {
      const question = RECORD.makeQuestion();

      expect(question.class_).toEqual(RECORD.class_);
    });
  });

  describe('serialise', () => {
    const recordNameWithoutDot = RECORD.name.replace(/\.$/, '');

    test('Record name should be serialised', () => {
      const serialisation = RECORD.serialise();

      expect(ANSWER.decode(serialisation)).toHaveProperty('name', recordNameWithoutDot);
    });

    test('Record type should be serialised', () => {
      const serialisation = RECORD.serialise();

      expect(ANSWER.decode(serialisation)).toHaveProperty('type', RECORD_TYPE_STR);
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

  describe('shallowCopy', () => {
    test('Nothing should be changed if nothing is overridden', () => {
      const newRecord = RECORD.shallowCopy({});

      expect(newRecord.name).toEqual(RECORD.name);
      expect(newRecord.type).toEqual(RECORD.type);
      expect(newRecord.class_).toEqual(RECORD.class_);
      expect(newRecord.ttl).toEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New name should be used if set', () => {
      const newName = `not-${RECORD.name}`;
      const newRecord = RECORD.shallowCopy({ name: newName });

      expect(newRecord.name).toEqual(newName);
      expect(newRecord.type).toEqual(RECORD.type);
      expect(newRecord.class_).toEqual(RECORD.class_);
      expect(newRecord.ttl).toEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New type should be used if set', () => {
      const newType = RECORD.type + 1;
      const newRecord = RECORD.shallowCopy({ type: newType });

      expect(newRecord.name).toEqual(RECORD.name);
      expect(newRecord.type).toEqual(newType);
      expect(newRecord.class_).toEqual(RECORD.class_);
      expect(newRecord.ttl).toEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New class should be used if set', () => {
      const newClass: any = 'foobar';
      const newRecord = RECORD.shallowCopy({ class: newClass });

      expect(newRecord.name).toEqual(RECORD.name);
      expect(newRecord.type).toEqual(RECORD.type);
      expect(newRecord.class_).toEqual(newClass);
      expect(newRecord.ttl).toEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New TTL should be used if set', () => {
      const newTtl = RECORD.ttl + 1;
      const newRecord = RECORD.shallowCopy({ ttl: newTtl });

      expect(newRecord.name).toEqual(RECORD.name);
      expect(newRecord.type).toEqual(RECORD.type);
      expect(newRecord.class_).toEqual(RECORD.class_);
      expect(newRecord.ttl).toEqual(newTtl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New data should be used if set', () => {
      const newData = Buffer.alloc(8);
      const newRecord = RECORD.shallowCopy({ dataSerialised: newData });

      expect(newRecord.name).toEqual(RECORD.name);
      expect(newRecord.type).toEqual(RECORD.type);
      expect(newRecord.class_).toEqual(RECORD.class_);
      expect(newRecord.ttl).toEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(newData);
    });
  });
});
