import { question } from '@leichtgewicht/dns-packet';

import { QUESTION, RECORD_CLASS_STR, RECORD_TYPE_STR } from '../../testUtils/dnsStubs';
import { Question } from './Question';
import { IANA_RR_TYPE_IDS, IANA_RR_TYPE_NAMES } from './ianaRrTypes';
import { DnsClass } from './DnsClass';
import { DnsError } from './DnsError';

describe('constructor', () => {
  describe('Type', () => {
    test('Id should be stored as is', () => {
      const question = new Question(QUESTION.name, IANA_RR_TYPE_IDS.A, DnsClass.IN);

      expect(question.typeId).toEqual(IANA_RR_TYPE_IDS.A);
    });

    test('Name should be converted to id', () => {
      const id = IANA_RR_TYPE_IDS.A;
      const name = IANA_RR_TYPE_NAMES[id];

      const question = new Question(QUESTION.name, name, DnsClass.IN);

      expect(question.typeId).toEqual(id);
    });

    test('Name not defined by IANA should cause an error', () => {
      const invalidName = 'BAZINGA' as any;

      expect(() => new Question(QUESTION.name, invalidName, DnsClass.IN)).toThrowWithMessage(
        DnsError,
        `RR type name "${invalidName}" is not defined by IANA`,
      );
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
    expect(QUESTION.getTypeName()).toEqual(RECORD_TYPE_STR);
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
    const differentQuestion = QUESTION.shallowCopy({ class: QUESTION.class_ + 1 });

    expect(QUESTION.equals(differentQuestion)).toBeFalse();
  });

  test('Questions with same attributes should be equal', () => {
    const equivalentQuestion = QUESTION.shallowCopy({});

    expect(QUESTION.equals(equivalentQuestion)).toBeTrue();
  });
});

describe('serialise', () => {
  test('Name should be serialised', () => {
    const serialisation = QUESTION.serialise();

    const deserialisation = question.decode(serialisation);
    expect(`${deserialisation.name}.`).toEqual(QUESTION.name);
  });

  test('Type should be serialised', () => {
    const serialisation = QUESTION.serialise();

    const deserialisation = question.decode(serialisation);
    expect(deserialisation.type).toEqual(RECORD_TYPE_STR);
  });

  test('Class should be serialised', () => {
    const serialisation = QUESTION.serialise();

    const deserialisation = question.decode(serialisation);
    expect(deserialisation.class).toEqual(RECORD_CLASS_STR);
  });
});

describe('shallowCopy', () => {
  test('Nothing should be changed if nothing is overridden', () => {
    const copy = QUESTION.shallowCopy({});

    expect(copy.name).toEqual(QUESTION.name);
    expect(copy.typeId).toEqual(QUESTION.typeId);
    expect(copy.class_).toEqual(QUESTION.class_);
  });

  test('New name should be used if set', () => {
    const newName = `sub.${QUESTION.name}`;

    const copy = QUESTION.shallowCopy({ name: newName });

    expect(copy.name).toEqual(newName);
    expect(copy.typeId).toEqual(QUESTION.typeId);
    expect(copy.class_).toEqual(QUESTION.class_);
  });

  test('New type should be used if set', () => {
    const newType = QUESTION.typeId + 1;

    const copy = QUESTION.shallowCopy({ type: newType });

    expect(copy.name).toEqual(QUESTION.name);
    expect(copy.typeId).toEqual(newType);
    expect(copy.class_).toEqual(QUESTION.class_);
  });

  test('New class should be used if set', () => {
    const newClass = QUESTION.class_ + 1;

    const copy = QUESTION.shallowCopy({ class: newClass });

    expect(copy.name).toEqual(QUESTION.name);
    expect(copy.typeId).toEqual(QUESTION.typeId);
    expect(copy.class_).toEqual(newClass);
  });
});
