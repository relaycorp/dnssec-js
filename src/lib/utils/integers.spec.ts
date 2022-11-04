import { getIntegerByteLength } from './integers';

describe('getIntegerBitLength', () => {
  test('Negative values should be unsupported', () => {
    expect(() => getIntegerByteLength(-1n)).toThrowWithMessage(
      Error,
      'Only positive values are supported (got -1)',
    );
  });

  test.each([
    [0n, 1],
    [1n, 1],
    [255n, 1],
    [256n, 2],
    [65535n, 2],
    [65536n, 3],
    [16777215n, 3],
    [16777216n, 4],
  ])('%s should have bit length %s', (integer, expectedBitLength) => {
    const bitLength = getIntegerByteLength(integer);

    expect(bitLength).toEqual(expectedBitLength);
  });
});
