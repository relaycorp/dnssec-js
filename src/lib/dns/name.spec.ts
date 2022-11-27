import { name as NAME } from '@leichtgewicht/dns-packet';

import { RECORD, RECORD_TLD } from '../../testUtils/dnsStubs.js';

import { countLabels, isChildZone, normaliseName, serialiseName } from './name.js';

describe('serialiseName', () => {
  const recordNameWithoutDot = RECORD.name.replace(/\.$/u, '');

  test('Trailing dot in record name should be ignored', () => {
    const name = `${recordNameWithoutDot}.`;

    const serialisation = serialiseName(name);

    expect(NAME.decode(serialisation)).toStrictEqual(recordNameWithoutDot);
  });

  test('Missing trailing dot in record name should be supported', () => {
    const serialisation = serialiseName(recordNameWithoutDot);

    expect(NAME.decode(serialisation)).toStrictEqual(recordNameWithoutDot);
  });

  test('Root name (dot) should be supported', () => {
    const serialisation = serialiseName('.');

    expect(serialisation).toStrictEqual(Buffer.from([0]));
  });
});

describe('normaliseName', () => {
  test('Missing trailing dot should be added', () => {
    const name = 'example.com';

    expect(normaliseName(name)).toBe(`${name}.`);
  });

  test('Present trailing dot should be left as is', () => {
    const name = 'example.com.';

    expect(normaliseName(name)).toStrictEqual(name);
  });

  test('Root should be left as is', () => {
    const name = '.';

    expect(normaliseName(name)).toStrictEqual(name);
  });
});

describe('countLabels', () => {
  test('Root name should have zero labels', () => {
    expect(countLabels('.')).toBe(0);
  });

  test('TLD should have one label', () => {
    expect(countLabels(RECORD_TLD)).toBe(1);
  });

  test('Apex domain should have two labels', () => {
    expect(countLabels(RECORD.name)).toBe(2);
  });

  test('Wildcard should not count towards labels', () => {
    expect(countLabels(`*.${RECORD.name}`)).toBe(2);
  });
});

describe('isChildZone', () => {
  test('Equal zones should return false', () => {
    expect(isChildZone('com.', 'com.')).toBeFalse();
  });

  test('Subdomain off tree should return false', () => {
    expect(isChildZone('example.com.', 'subdomain.example.org.')).toBeFalse();
  });

  test('Subdomain should return true', () => {
    expect(isChildZone('example.com.', 'subdomain.example.com.')).toBeTrue();
  });

  test('Any zone should be regarded a child of the root', () => {
    expect(isChildZone('.', '.')).toBeTrue();
    expect(isChildZone('.', 'com.')).toBeTrue();
    expect(isChildZone('.', 'example.com.')).toBeTrue();
  });
});
