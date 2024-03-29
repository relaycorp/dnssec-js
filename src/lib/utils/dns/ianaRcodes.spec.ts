import { getRcodeId, RCODE_IDS, type RcodeIdOrName } from './ianaRcodes.js';
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
