import { bigintToBuf } from 'bigint-conversion';

export function bigintToPaddedBuffer(bigInt: bigint, length: number): Buffer {
  const bigIntBuffer = bigintToBuf(bigInt) as Buffer;

  if (bigIntBuffer.byteLength === length) {
    return bigIntBuffer;
  }

  if (length < bigIntBuffer.byteLength) {
    throw new Error(
      'Required buffer length is insufficient ' +
        `(needed ${bigIntBuffer.byteLength} bytes, provided ${length})`,
    );
  }

  const padding = Buffer.alloc(length - bigIntBuffer.byteLength);

  return Buffer.concat([padding, bigIntBuffer]);
}
