import type { RcodeIdOrName } from './ianaRcodes.js';
import { getRcodeId, getRcodeName, RCODE_IDS } from './ianaRcodes.js';
import { DnsError } from './DnsError.js';

describe('getRcodeId', () => {
  test('Input should be returned if it already is a number', () => {
    expect(getRcodeId(RCODE_IDS.NOERROR)).toStrictEqual(RCODE_IDS.NOERROR);
  });

  test('Name should be converted to id', () => {
    expect(getRcodeId('NOERROR')).toStrictEqual(RCODE_IDS.NOERROR);
  });

  test('Name lookup should be case-insensitive', () => {
    expect(getRcodeId('NOERROR' as RcodeIdOrName)).toStrictEqual(RCODE_IDS.NOERROR);
  });

  test('Code not defined by IANA should cause an error', () => {
    const invalidName = 'BAZINGA' as RcodeIdOrName;

    expect(() => getRcodeId(invalidName)).toThrowWithMessage(
      DnsError,
      `DNS RCode name "${invalidName}" is not defined by IANA`,
    );
  });
});

describe('getRcodeName', () => {
  test('Id should be converted to name', () => {
    expect(getRcodeName(RCODE_IDS.NOERROR)).toBe('NOERROR');
  });

  test('Id not defined by IANA should cause an error', () => {
    const invalidId = Math.max(...Object.values(RCODE_IDS)) + 1;

    expect(() => getRcodeName(invalidId)).toThrowWithMessage(
      DnsError,
      `DNS RCode id ${invalidId} is not defined by IANA`,
    );
  });
});
