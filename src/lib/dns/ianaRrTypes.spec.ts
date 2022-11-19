import { IANA_RR_TYPE_IDS, IANA_RR_TYPE_NAMES } from './ianaRrTypes';

describe('IANA_RR_TYPE_NAMES', () => {
  test.each(Object.entries(IANA_RR_TYPE_IDS))(
    'Name "%s" should correspond to id %s',
    (expectedName, id) => {
      const name = IANA_RR_TYPE_NAMES[id];

      expect(name).toEqual(expectedName);
    },
  );
});
