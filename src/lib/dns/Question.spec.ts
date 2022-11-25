import { QUESTION, RECORD_TYPE_STR } from '../../testUtils/dnsStubs';

import { Question } from './Question';
import { IANA_RR_TYPE_IDS, IANA_RR_TYPE_NAMES } from './ianaRrTypes';
import { DnsError } from './DnsError';
import { DnsClass } from './ianaClasses';

describe('constructor', () => {
  describe('Name', () => {
    test('Missing trailing dot should be added', () => {
      const name = 'example.com';
      const question = new Question(name, QUESTION.typeId, QUESTION.classId);

      expect(question.name).toBe(`${name}.`);
    });

    test('Present trailing dot should be left as is', () => {
      const name = 'example.com.';
      const question = new Question(name, QUESTION.typeId, QUESTION.classId);

      expect(question.name).toStrictEqual(name);
    });
  });

  describe('Type', () => {
    test('Id should be stored as is', () => {
      const question = new Question(QUESTION.name, IANA_RR_TYPE_IDS.A, DnsClass.IN);

      expect(question.typeId).toStrictEqual(IANA_RR_TYPE_IDS.A);
    });

    test('Name should be converted to id', () => {
      const id = IANA_RR_TYPE_IDS.A;
      const name = IANA_RR_TYPE_NAMES[id];

      const question = new Question(QUESTION.name, name, DnsClass.IN);

      expect(question.typeId).toStrictEqual(id);
    });
  });

  describe('Class', () => {
    test('IN class should be used by default', () => {
      const question = new Question(QUESTION.name, IANA_RR_TYPE_IDS.A);

      expect(question.classId).toStrictEqual(DnsClass.IN);
    });

    test('Id should be stored as is', () => {
      const question = new Question(QUESTION.name, IANA_RR_TYPE_IDS.A, DnsClass.IN);

      expect(question.classId).toStrictEqual(DnsClass.IN);
    });

    test('Name should be converted to id', () => {
      const question = new Question(QUESTION.name, QUESTION.typeId, 'CH');

      expect(question.classId).toStrictEqual(DnsClass.CH);
    });
  });
});

describe('key', () => {
  test('Key should start with name', () => {
    expect(QUESTION.key).toStartWith(`${QUESTION.name}/`);
  });

  test('Key should end with type id', () => {
    expect(QUESTION.key).toEndWith(`/${QUESTION.typeId}`);
  });
});

describe('getTypeName', () => {
  test('Name should be returned if defined by IANA', () => {
    expect(QUESTION.getTypeName()).toStrictEqual(RECORD_TYPE_STR);
  });

  test('Error should be thrown if not defined by IANA', () => {
    const reservedType = 0;
    const question = QUESTION.shallowCopy({ type: reservedType });

    expect(() => question.getTypeName()).toThrowWithMessage(
      DnsError,
      `RR type id ${reservedType} is not defined by IANA`,
    );
  });
});

describe('equals', () => {
  test('Questions with different names should be unequal', () => {
    const differentQuestion = QUESTION.shallowCopy({ name: `sub.${QUESTION.name}` });

    expect(QUESTION.equals(differentQuestion)).toBeFalse();
  });

  test('Questions with different types should be unequal', () => {
    const differentQuestion = QUESTION.shallowCopy({ type: QUESTION.typeId + 1 });

    expect(QUESTION.equals(differentQuestion)).toBeFalse();
  });

  test('Questions with different classes should be unequal', () => {
    const differentQuestion = QUESTION.shallowCopy({ class: QUESTION.classId + 1 });

    expect(QUESTION.equals(differentQuestion)).toBeFalse();
  });

  test('Questions with same attributes should be equal', () => {
    const equivalentQuestion = QUESTION.shallowCopy({});

    expect(QUESTION.equals(equivalentQuestion)).toBeTrue();
  });
});

describe('shallowCopy', () => {
  test('Nothing should be changed if nothing is overridden', () => {
    const copy = QUESTION.shallowCopy({});

    expect(copy.name).toStrictEqual(QUESTION.name);
    expect(copy.typeId).toStrictEqual(QUESTION.typeId);
    expect(copy.classId).toStrictEqual(QUESTION.classId);
  });

  test('New name should be used if set', () => {
    const newName = `sub.${QUESTION.name}`;

    const copy = QUESTION.shallowCopy({ name: newName });

    expect(copy.name).toStrictEqual(newName);
    expect(copy.typeId).toStrictEqual(QUESTION.typeId);
    expect(copy.classId).toStrictEqual(QUESTION.classId);
  });

  test('New type should be used if set', () => {
    const newType = QUESTION.typeId + 1;

    const copy = QUESTION.shallowCopy({ type: newType });

    expect(copy.name).toStrictEqual(QUESTION.name);
    expect(copy.typeId).toStrictEqual(newType);
    expect(copy.classId).toStrictEqual(QUESTION.classId);
  });

  test('New class should be used if set', () => {
    const newClass = QUESTION.classId + 1;

    const copy = QUESTION.shallowCopy({ class: newClass });

    expect(copy.name).toStrictEqual(QUESTION.name);
    expect(copy.typeId).toStrictEqual(QUESTION.typeId);
    expect(copy.classId).toStrictEqual(newClass);
  });
});
