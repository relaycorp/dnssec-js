import { DnsClass, getDnsClassId } from './ianaClasses';
import { DnsError } from './DnsError';

describe('getDnsClassId', () => {
  test('Input should be returned if it already is a number', () => {
    expect(getDnsClassId(DnsClass.CH)).toEqual(DnsClass.CH);
  });

  test('Name should be converted to id', () => {
    expect(getDnsClassId('CH')).toEqual(DnsClass.CH);
  });

  test('Class not defined by IANA should cause an error', () => {
    const invalidName = 'BAZINGA' as any;

    expect(() => getDnsClassId(invalidName)).toThrowWithMessage(
      DnsError,
      `DNS class "${invalidName}" is not defined by IANA`,
    );
  });
});
