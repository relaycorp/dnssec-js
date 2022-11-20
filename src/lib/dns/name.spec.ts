import { name as NAME } from '@leichtgewicht/dns-packet';

import { RECORD, RECORD_TLD } from '../../testUtils/dnsStubs';
import { NAME_PARSER_OPTIONS, normaliseName, serialiseName } from './name';
import { Parser } from 'binary-parser';

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

describe('Parser', () => {
  const PARSER = new Parser().array('name', NAME_PARSER_OPTIONS);

  test('Root name (dot) should be deserialised', () => {
    const name = '.';
    const serialisation = serialiseName(name);

    const nameDeserialised = PARSER.parse(serialisation);

    expect(nameDeserialised.name).toEqual(name);
  });

  test('TLD should be deserialised', () => {
    const serialisation = serialiseName(RECORD_TLD);

    const nameDeserialised = PARSER.parse(serialisation);

    expect(nameDeserialised.name).toEqual(RECORD_TLD);
  });
});
