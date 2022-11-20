import { name as NAME } from '@leichtgewicht/dns-packet';

import { RECORD } from '../../testUtils/dnsStubs';
import {  normaliseName, serialiseName } from './name';

describe('serialiseName', () => {
  const recordNameWithoutDot = RECORD.name.replace(/\.$/, '');

  test('Trailing dot in record name should be ignored', () => {
    const name = recordNameWithoutDot + '.';

    const serialisation = serialiseName(name);

    expect(NAME.decode(serialisation)).toEqual(recordNameWithoutDot);
  });

  test('Missing trailing dot in record name should be supported', () => {
    const serialisation = serialiseName(recordNameWithoutDot);

    expect(NAME.decode(serialisation)).toEqual(recordNameWithoutDot);
  });

  test('Root name (dot) should be supported', () => {
    const serialisation = serialiseName('.');

    expect(serialisation).toEqual(Buffer.from([0]));
  });
});

describe('normaliseName', () => {
  test('Missing trailing dot should be added', () => {
    const name = 'example.com';

    expect(normaliseName(name)).toEqual(`${name}.`);
  });

  test('Present trailing dot should be left as is', () => {
    const name = 'example.com.';

    expect(normaliseName(name)).toEqual(name);
  });

  test('Root should be left as is', () => {
    const name = '.';

    expect(normaliseName(name)).toEqual(name);
  });
});
