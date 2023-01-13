import type { DnsClassName } from './ianaClasses.js';
import { DnsClass, getDnsClassId, getDnsClassName } from './ianaClasses.js';
import { DnsError } from './DnsError.js';

describe('getDnsClassId', () => {
  test('Input should be returned if it already is a number', () => {
    expect(getDnsClassId(DnsClass.CH)).toStrictEqual(DnsClass.CH);
  });

  test('Name should be converted to id', () => {
    expect(getDnsClassId('CH')).toStrictEqual(DnsClass.CH);
  });

  test('Class not defined by IANA should cause an error', () => {
    const invalidName = 'BAZINGA' as DnsClassName;

    expect(() => getDnsClassId(invalidName)).toThrowWithMessage(
      DnsError,
      `DNS class name "${invalidName}" is not defined by IANA`,
    );
  });
});

describe('getDnsClassName', () => {
  test('Id should be converted to name', () => {
    expect(getDnsClassName(DnsClass.CH)).toBe('CH');
  });

  test('Class not defined by IANA should cause an error', () => {
    const invalidId = 42 as DnsClass;

    expect(() => getDnsClassName(invalidId)).toThrowWithMessage(
      DnsError,
      `DNS class id "${invalidId}" is not defined by IANA`,
    );
  });
});
