import { name as NAME } from '@leichtgewicht/dns-packet';

import { RECORD_NAME } from '../../testUtils/stubs';
import { serialiseName } from './name';

describe('serialiseName', () => {
  const recordNameWithoutDot = RECORD_NAME.replace(/\.$/, '');

  test('Trailing dot in record name should be ignored', () => {
    const name = recordNameWithoutDot + '.';

    const serialisation = serialiseName(name);

    expect(NAME.decode(serialisation)).toEqual(recordNameWithoutDot);
  });

  test('Missing trailing dot in record name should be supported', () => {
    const serialisation = serialiseName(recordNameWithoutDot);

    expect(NAME.decode(serialisation)).toEqual(recordNameWithoutDot);
  });
});
