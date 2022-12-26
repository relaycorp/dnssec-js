import type { MxData, TxtAnswer } from '@leichtgewicht/dns-packet';
import { answer as ANSWER, mx } from '@leichtgewicht/dns-packet';

import {
  RECORD,
  RECORD_CLASS_STR,
  RECORD_DATA_TXT_DATA,
  RECORD_TYPE_STR,
} from '../../testUtils/dnsStubs.js';

import { DnsRecord } from './DnsRecord.js';
import type { IanaRrTypeName } from './ianaRrTypes.js';
import { getRrTypeName, IANA_RR_TYPE_IDS, IANA_RR_TYPE_NAMES } from './ianaRrTypes.js';
import { DnsError } from './DnsError.js';
import { DnsClass } from './ianaClasses.js';

describe('DnsRecord', () => {
  describe('constructor', () => {
    describe('Name', () => {
      test('Missing trailing dot should be added', () => {
        const name = 'example.com';
        const record = new DnsRecord(
          name,
          RECORD.typeId,
          DnsClass.IN,
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.name).toBe(`${name}.`);
      });

      test('Present trailing dot should be left as is', () => {
        const name = 'example.com.';
        const record = new DnsRecord(
          name,
          RECORD.typeId,
          DnsClass.IN,
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.name).toStrictEqual(name);
      });
    });

    describe('Type', () => {
      const stubId = IANA_RR_TYPE_IDS.A;

      test('Id should be stored as is', () => {
        const record = new DnsRecord(
          RECORD.name,
          stubId,
          RECORD.classId,
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.typeId).toStrictEqual(stubId);
      });

      test('Name should be converted to id', () => {
        const record = new DnsRecord(
          RECORD.name,
          IANA_RR_TYPE_NAMES[stubId],
          RECORD.classId,
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.typeId).toStrictEqual(stubId);
      });

      test('Name not defined by IANA should cause an error', () => {
        const invalidName = 'BAZINGA' as IanaRrTypeName;

        expect(
          () =>
            new DnsRecord(
              RECORD.name,
              invalidName,
              RECORD.classId,
              RECORD.ttl,
              RECORD.dataSerialised,
            ),
        ).toThrowWithMessage(DnsError, `RR type name "${invalidName}" is not defined by IANA`);
      });
    });

    describe('Class', () => {
      test('Id should be stored as is', () => {
        const record = new DnsRecord(
          RECORD.name,
          RECORD.typeId,
          DnsClass.CH,
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.classId).toStrictEqual(DnsClass.CH);
      });

      test('Name should be converted to id', () => {
        const record = new DnsRecord(
          RECORD.name,
          RECORD.typeId,
          'CH',
          RECORD.ttl,
          RECORD.dataSerialised,
        );

        expect(record.classId).toStrictEqual(DnsClass.CH);
      });
    });

    describe('Data', () => {
      const stubTypeId = IANA_RR_TYPE_IDS.MX;
      const stubTypeName = getRrTypeName(stubTypeId);
      const stubData: MxData = { exchange: 'foo', preference: 3 };

      // Chop off length prefix
      const stubDataSerialised = Buffer.from(mx.encode(stubData)).subarray(2);

      describe('Serialised', () => {
        test('Buffer should be stored as is', () => {
          const record = new DnsRecord(
            RECORD.name,
            stubTypeId,
            RECORD.classId,
            RECORD.ttl,
            stubDataSerialised,
          );

          expect(record.dataSerialised).toStrictEqual(stubDataSerialised);
        });

        test('Data should be deserialised', () => {
          const record = new DnsRecord(
            RECORD.name,
            stubTypeId,
            RECORD.classId,
            RECORD.ttl,
            stubDataSerialised,
          );

          expect(record.dataFields).toStrictEqual(stubData);
        });

        test('Malformed data should be refused', () => {
          const malformedData = Buffer.allocUnsafe(1);

          expect(
            () => new DnsRecord(RECORD.name, stubTypeId, RECORD.classId, RECORD.ttl, malformedData),
          ).toThrowWithMessage(DnsError, `Data for record type ${stubTypeName} is malformed`);
        });
      });

      describe('Deserialised', () => {
        test('Buffer should be computed and stored if data is valid', () => {
          const record = new DnsRecord(
            RECORD.name,
            stubTypeId,
            RECORD.classId,
            RECORD.ttl,
            stubData,
          );

          expect(record.dataSerialised).toStrictEqual(stubDataSerialised);
        });

        test('Data should be stored as is if valid', () => {
          const record = new DnsRecord(
            RECORD.name,
            stubTypeId,
            RECORD.classId,
            RECORD.ttl,
            stubData,
          );

          expect(record.dataFields).toStrictEqual(stubData);
        });

        test('Invalid data should be refused', () => {
          const invalidData = {};

          expect(
            () => new DnsRecord(RECORD.name, stubTypeId, RECORD.classId, RECORD.ttl, invalidData),
          ).toThrowWithMessage(DnsError, `Data for record type ${stubTypeName} is invalid`);
        });
      });
    });
  });

  describe('question', () => {
    test('Name should be set', () => {
      const question = RECORD.makeQuestion();

      expect(question.name).toStrictEqual(RECORD.name);
    });

    test('Type should be set', () => {
      const question = RECORD.makeQuestion();

      expect(question.typeId).toStrictEqual(RECORD.typeId);
    });

    test('Class should be set', () => {
      const question = RECORD.makeQuestion();

      expect(question.classId).toStrictEqual(RECORD.classId);
    });
  });

  describe('serialise', () => {
    const recordNameWithoutDot = RECORD.name.replace(/\.$/u, '');

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
      expect(RECORD_DATA_TXT_DATA.equals(record.data[0] as Uint8Array)).toBeTrue();
    });
  });

  describe('shallowCopy', () => {
    test('Nothing should be changed if nothing is overridden', () => {
      const newRecord = RECORD.shallowCopy({});

      expect(newRecord.name).toStrictEqual(RECORD.name);
      expect(newRecord.typeId).toStrictEqual(RECORD.typeId);
      expect(newRecord.classId).toStrictEqual(RECORD.classId);
      expect(newRecord.ttl).toStrictEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New name should be used if set', () => {
      const newName = `not-${RECORD.name}`;
      const newRecord = RECORD.shallowCopy({ name: newName });

      expect(newRecord.name).toStrictEqual(newName);
      expect(newRecord.typeId).toStrictEqual(RECORD.typeId);
      expect(newRecord.classId).toStrictEqual(RECORD.classId);
      expect(newRecord.ttl).toStrictEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New type should be used if set', () => {
      const newType = IANA_RR_TYPE_IDS.A;
      expect(newType).not.toStrictEqual(RECORD.typeId);
      const newRecord = RECORD.shallowCopy({ type: newType });

      expect(newRecord.name).toStrictEqual(RECORD.name);
      expect(newRecord.typeId).toStrictEqual(newType);
      expect(newRecord.classId).toStrictEqual(RECORD.classId);
      expect(newRecord.ttl).toStrictEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New class should be used if set', () => {
      const newClass = DnsClass.CH;
      expect(newClass).not.toStrictEqual(RECORD);
      const newRecord = RECORD.shallowCopy({ class: newClass });

      expect(newRecord.name).toStrictEqual(RECORD.name);
      expect(newRecord.typeId).toStrictEqual(RECORD.typeId);
      expect(newRecord.classId).toStrictEqual(newClass);
      expect(newRecord.ttl).toStrictEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New TTL should be used if set', () => {
      const newTtl = RECORD.ttl + 1;
      const newRecord = RECORD.shallowCopy({ ttl: newTtl });

      expect(newRecord.name).toStrictEqual(RECORD.name);
      expect(newRecord.typeId).toStrictEqual(RECORD.typeId);
      expect(newRecord.classId).toStrictEqual(RECORD.classId);
      expect(newRecord.ttl).toStrictEqual(newTtl);
      expect(newRecord.dataSerialised).toBe(RECORD.dataSerialised);
    });

    test('New data should be used if set', () => {
      const newData = Buffer.alloc(8);
      const newRecord = RECORD.shallowCopy({ dataSerialised: newData });

      expect(newRecord.name).toStrictEqual(RECORD.name);
      expect(newRecord.typeId).toStrictEqual(RECORD.typeId);
      expect(newRecord.classId).toStrictEqual(RECORD.classId);
      expect(newRecord.ttl).toStrictEqual(RECORD.ttl);
      expect(newRecord.dataSerialised).toBe(newData);
    });
  });
});
