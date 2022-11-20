import { getRcodeId, RCODE_IDS } from './ianaRcodes';
import { DnsError } from './DnsError';

describe('getRcodeId', () => {
  test('Input should be returned if it already is a number', () => {
    expect(getRcodeId(RCODE_IDS.NoError)).toEqual(RCODE_IDS.NoError);
  });

  test('Name should be converted to id', () => {
    expect(getRcodeId('NoError')).toEqual(RCODE_IDS.NoError);
  });

  test('Name lookup should be case-insensitive', () => {
    expect(getRcodeId('NOERROR' as any)).toEqual(RCODE_IDS.NoError);
  });

  test('Code not defined by IANA should cause an error', () => {
    const invalidName = 'BAZINGA' as any;

    expect(() => getRcodeId(invalidName)).toThrowWithMessage(
      DnsError,
      `DNS RCode "${invalidName}" is not defined by IANA`,
    );
  });
});
