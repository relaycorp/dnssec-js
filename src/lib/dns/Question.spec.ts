import { question } from '@leichtgewicht/dns-packet';

import { QUESTION, RECORD_CLASS_STR, RECORD_TYPE_STR } from '../../testUtils/dnsStubs';

describe('key', () => {
  test('Key should start with name', () => {
    expect(QUESTION.key).toStartWith(`${QUESTION.name}/`);
  });

  test('Key should end with type id', () => {
    expect(QUESTION.key).toEndWith(`/${QUESTION.type}`);
  });
});

describe('equals', () => {
  test('Questions with different names should be unequal', () => {
    const differentQuestion = QUESTION.shallowCopy({ name: `sub.${QUESTION.name}` });

    expect(QUESTION.equals(differentQuestion)).toBeFalse();
  });

  test('Questions with different types should be unequal', () => {
    const differentQuestion = QUESTION.shallowCopy({ type: QUESTION.type + 1 });

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
    expect(copy.type).toEqual(QUESTION.type);
    expect(copy.class_).toEqual(QUESTION.class_);
  });

  test('New name should be used if set', () => {
    const newName = `sub.${QUESTION.name}`;

    const copy = QUESTION.shallowCopy({ name: newName });

    expect(copy.name).toEqual(newName);
    expect(copy.type).toEqual(QUESTION.type);
    expect(copy.class_).toEqual(QUESTION.class_);
  });

  test('New type should be used if set', () => {
    const newType = QUESTION.type + 1;

    const copy = QUESTION.shallowCopy({ type: newType });

    expect(copy.name).toEqual(QUESTION.name);
    expect(copy.type).toEqual(newType);
    expect(copy.class_).toEqual(QUESTION.class_);
  });

  test('New class should be used if set', () => {
    const newClass = QUESTION.class_ + 1;

    const copy = QUESTION.shallowCopy({ class: newClass });

    expect(copy.name).toEqual(QUESTION.name);
    expect(copy.type).toEqual(QUESTION.type);
    expect(copy.class_).toEqual(newClass);
  });
});
