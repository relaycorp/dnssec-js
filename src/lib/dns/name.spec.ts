import { name as NAME } from '@leichtgewicht/dns-packet';

import { RECORD, RECORD_TLD } from '../../testUtils/dnsStubs';
import { NAME_PARSER_OPTIONS, serialiseName } from './name';
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
