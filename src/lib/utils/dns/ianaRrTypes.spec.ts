import type { IanaRrTypeName } from './ianaRrTypes.js';
import { getRrTypeId, getRrTypeName, IANA_RR_TYPE_IDS, IANA_RR_TYPE_NAMES } from './ianaRrTypes.js';
import { DnsError } from './DnsError.js';

describe('IANA_RR_TYPE_NAMES', () => {
  test.each(Object.entries(IANA_RR_TYPE_IDS))(
    'Name "%s" should correspond to id %s',
    (expectedName, id) => {
      const name = IANA_RR_TYPE_NAMES[id];

      expect(name).toStrictEqual(expectedName);
    },
  );
});

describe('getRrTypeId', () => {
  test('Input should be returned if it already is a number', () => {
    expect(getRrTypeId(IANA_RR_TYPE_IDS.A)).toStrictEqual(IANA_RR_TYPE_IDS.A);
  });

  test('Name should be converted to id', () => {
    expect(getRrTypeId('A')).toStrictEqual(IANA_RR_TYPE_IDS.A);
  });

  test('Type not defined by IANA should cause an error', () => {
    const invalidName = 'BAZINGA' as IanaRrTypeName;

    expect(() => getRrTypeId(invalidName)).toThrowWithMessage(
      DnsError,
      `RR type name "${invalidName}" is not defined by IANA`,
    );
  });
});

describe('getRrTypeName', () => {
  test('Input should be returned if it already is a string', () => {
    const name = 'TXT';

    expect(getRrTypeName(name)).toStrictEqual(name);
  });

  test('Id should be converted to name', () => {
    expect(getRrTypeName(IANA_RR_TYPE_IDS.TXT)).toBe('TXT');
  });

  test('Id not defined by IANA should cause an error', () => {
    const invalidId = 0;

    expect(() => getRrTypeName(invalidId)).toThrowWithMessage(
      DnsError,
      `RR type id "${invalidId}" is not defined by IANA`,
    );
  });
});
