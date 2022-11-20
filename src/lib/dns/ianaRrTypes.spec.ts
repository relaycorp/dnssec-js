import { getRrTypeId, getRrTypeName, IANA_RR_TYPE_IDS, IANA_RR_TYPE_NAMES } from './ianaRrTypes';
import { DnsError } from './DnsError';

describe('IANA_RR_TYPE_NAMES', () => {
  test.each(Object.entries(IANA_RR_TYPE_IDS))(
    'Name "%s" should correspond to id %s',
    (expectedName, id) => {
      const name = IANA_RR_TYPE_NAMES[id];

      expect(name).toEqual(expectedName);
    },
  );
});

describe('getRrTypeId', () => {
  test('Input should be returned if it already is a number', () => {
    expect(getRrTypeId(IANA_RR_TYPE_IDS.A)).toEqual(IANA_RR_TYPE_IDS.A);
  });

  test('Name should be converted to id', () => {
    expect(getRrTypeId('A')).toEqual(IANA_RR_TYPE_IDS.A);
  });

  test('Type not defined by IANA should cause an error', () => {
    const invalidName = 'BAZINGA' as any;

    expect(() => getRrTypeId(invalidName)).toThrowWithMessage(
      DnsError,
      `RR type name "${invalidName}" is not defined by IANA`,
    );
  });
});

describe('getRrTypeName', () => {
  test('Input should be returned if it already is a string', () => {
    const name = 'TXT';

    expect(getRrTypeName(name)).toEqual(name);
  });

  test('Id should be converted to name', () => {
    expect(getRrTypeName(IANA_RR_TYPE_IDS.TXT)).toEqual('TXT');
  });

  test('Id not defined by IANA should cause an error', () => {
    const invalidId = 0;

    expect(() => getRrTypeName(invalidId)).toThrowWithMessage(
      DnsError,
      `RR type id "${invalidId}" is not defined by IANA`,
    );
  });
});
