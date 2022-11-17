export function getIntegerByteLength(integer: bigint): number {
  if (integer < 0n) {
    throw new Error(`Only positive values are supported (got ${integer})`);
  }
  // The least horrible way to get the bit length: https://stackoverflow.com/a/54758235/129437
  const bitLength = integer.toString(2).length;
  return Math.ceil(bitLength / 8);
}
