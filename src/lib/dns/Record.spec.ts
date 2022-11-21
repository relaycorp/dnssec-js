import { answer as ANSWER, mx, MxData, TxtAnswer } from '@leichtgewicht/dns-packet';

import {
  RECORD,
  RECORD_CLASS_STR,
  RECORD_DATA_TXT_DATA,
  RECORD_TYPE_STR,
} from '../../testUtils/dnsStubs';
import { Record } from './Record';
import { getRrTypeName, IANA_RR_TYPE_IDS, IANA_RR_TYPE_NAMES } from './ianaRrTypes';
import { DnsError } from './DnsError';
import { DnsClass } from './ianaClasses';

describe('Record', () => {
  describe('constructor', () => {
    describe('Name', () => {
      test('Missing trailing dot should be added', () => {
        const name = 'example.com';
        const record = new Record(
          name,
          RECORD.typeId,
          DnsClass.IN,
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.name).toEqual(`${name}.`);
      });

      test('Present trailing dot should be left as is', () => {
        const name = 'example.com.';
        const record = new Record(
          name,
          RECORD.typeId,
          DnsClass.IN,
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.name).toEqual(name);
      });
    });

    describe('Type', () => {
      const ID = IANA_RR_TYPE_IDS.A;

      test('Id should be stored as is', () => {
        const record = new Record(
          RECORD.name,
          ID,
          RECORD.class_,
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.typeId).toEqual(ID);
      });

      test('Name should be converted to id', () => {
        const record = new Record(
          RECORD.name,
          IANA_RR_TYPE_NAMES[ID],
          RECORD.class_,
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.typeId).toEqual(ID);
      });

      test('Name not defined by IANA should cause an error', () => {
        const invalidName = 'BAZINGA' as any;

        expect(
          () =>
            new Record(RECORD.name, invalidName, RECORD.class_, RECORD.ttl, RECORD.dataSerialised),
        ).toThrowWithMessage(DnsError, `RR type name "${invalidName}" is not defined by IANA`);
      });
    });

    describe('Class', () => {
      test('Id should be stored as is', () => {
        const record = new Record(
          RECORD.name,
          RECORD.typeId,
          DnsClass.CH,
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.class_).toEqual(DnsClass.CH);
      });

      test('Name should be converted to id', () => {
        const record = new Record(
          RECORD.name,
          RECORD.typeId,
          'CH',
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.class_).toEqual(DnsClass.CH);
      });
    });

    describe('Data', () => {
      const TYPE_ID = IANA_RR_TYPE_IDS.MX;
      const TYYPE_NAME = getRrTypeName(TYPE_ID);
      const DATA: MxData = { exchange: 'foo', preference: 3 };
      const DATA_SERIALISED = Buffer.from(mx.encode(DATA)).subarray(2); // Chop off length prefix

      describe('Serialised', () => {
        test('Buffer should be stored as is', () => {
          const record = new Record(
            RECORD.name,
            TYPE_ID,
            RECORD.class_,
            RECORD.ttl,
            DATA_SERIALISED,
          );

          expect(record.dataSerialised).toEqual(DATA_SERIALISED);
        });

        test('Data should be deserialised', () => {
          const record = new Record(
            RECORD.name,
            TYPE_ID,
            RECORD.class_,
            RECORD.ttl,
            DATA_SERIALISED,
          );

          expect(record.dataFields).toEqual(DATA);
        });

        test('Malformed data should be refused', () => {
          const malformedData = Buffer.allocUnsafe(1);

          expect(
            () => new Record(RECORD.name, TYPE_ID, RECORD.class_, RECORD.ttl, malformedData),
          ).toThrowWithMessage(DnsError, `Data for record type ${TYYPE_NAME} is malformed`);
        });
      });

      describe('Deserialised', () => {
        test('Buffer should be computed and stored if data is valid', () => {
          const record = new Record(RECORD.name, TYPE_ID, RECORD.class_, RECORD.ttl, DATA);

          expect(record.dataSerialised).toEqual(DATA_SERIALISED);
        });

        test('Data should be stored as is if valid', () => {
          const record = new Record(RECORD.name, TYPE_ID, RECORD.class_, RECORD.ttl, DATA);

          expect(record.dataFields).toEqual(DATA);
        });

        test('Invalid data should be refused', () => {
          const invalidData = {};

          expect(
            () => new Record(RECORD.name, TYPE_ID, RECORD.class_, RECORD.ttl, invalidData),
          ).toThrowWithMessage(DnsError, `Data for record type ${TYYPE_NAME} is invalid`);
        });
      });
    });
  });

  describe('question', () => {
    test('Name should be set', () => {
      const question = RECORD.makeQuestion();

      expect(question.name).toEqual(RECORD.name);
    });

    test('Type should be set', () => {
      const question = RECORD.makeQuestion();

      expect(question.typeId).toEqual(RECORD.typeId);
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

    test('Record TTL should be overridable', () => {
      const differentTtl = RECORD.ttl + 1;

      const serialisation = RECORD.serialise(differentTtl);

      expect(ANSWER.decode(serialisation)).toHaveProperty('ttl', differentTtl);
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
      expect(newRecord.typeId).toEqual(RECORD.typeId);
      expect(newRecord.class_).toEqual(RECORD.class_);
      expect(newRecord.ttl).toEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New name should be used if set', () => {
      const newName = `not-${RECORD.name}`;
      const newRecord = RECORD.shallowCopy({ name: newName });

      expect(newRecord.name).toEqual(newName);
      expect(newRecord.typeId).toEqual(RECORD.typeId);
      expect(newRecord.class_).toEqual(RECORD.class_);
      expect(newRecord.ttl).toEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New type should be used if set', () => {
      const newType = IANA_RR_TYPE_IDS.A;
      expect(newType).not.toEqual(RECORD.typeId);
      const newRecord = RECORD.shallowCopy({ type: newType });

      expect(newRecord.name).toEqual(RECORD.name);
      expect(newRecord.typeId).toEqual(newType);
      expect(newRecord.class_).toEqual(RECORD.class_);
      expect(newRecord.ttl).toEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New class should be used if set', () => {
      const newClass = DnsClass.CH;
      expect(newClass).not.toEqual(RECORD);
      const newRecord = RECORD.shallowCopy({ class: newClass });

      expect(newRecord.name).toEqual(RECORD.name);
      expect(newRecord.typeId).toEqual(RECORD.typeId);
      expect(newRecord.class_).toEqual(newClass);
      expect(newRecord.ttl).toEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New TTL should be used if set', () => {
      const newTtl = RECORD.ttl + 1;
      const newRecord = RECORD.shallowCopy({ ttl: newTtl });

      expect(newRecord.name).toEqual(RECORD.name);
      expect(newRecord.typeId).toEqual(RECORD.typeId);
      expect(newRecord.class_).toEqual(RECORD.class_);
      expect(newRecord.ttl).toEqual(newTtl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New data should be used if set', () => {
      const newData = Buffer.alloc(8);
      const newRecord = RECORD.shallowCopy({ dataSerialised: newData });

      expect(newRecord.name).toEqual(RECORD.name);
      expect(newRecord.typeId).toEqual(RECORD.typeId);
      expect(newRecord.class_).toEqual(RECORD.class_);
      expect(newRecord.ttl).toEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(newData);
    });
  });
});
