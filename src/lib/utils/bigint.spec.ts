import { bigintToPaddedBuffer } from './bigint.js';

describe('bigintToPaddedBuffer', () => {
  test('should error out if requested length is insufficient', () => {
    const bigInt = BigInt(256);

    expect(() => bigintToPaddedBuffer(bigInt, 1)).toThrow(
      'Required buffer length is insufficient (needed 2 bytes, provided 1)',
    );
  });

  test('should pad with zeros if requested length is greater needed', () => {
    const bigInt = BigInt(255);

    expect(bigintToPaddedBuffer(bigInt, 2)).toStrictEqual(Buffer.from([0, 255]));
  });

  test('should return a buffer of the requested length', () => {
    const bigInt = BigInt(255);

    expect(bigintToPaddedBuffer(bigInt, 1)).toStrictEqual(Buffer.from([255]));
  });
});
