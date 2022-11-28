import type { DnsClassName } from './ianaClasses.js';
import { DnsClass, getDnsClassId } from './ianaClasses.js';
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
      `DNS class "${invalidName}" is not defined by IANA`,
    );
  });
});