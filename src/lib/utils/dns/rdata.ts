export function lengthPrefixRdata(rdata: Buffer): Buffer {
  // eslint-disable-next-line @typescript-eslint/no-magic-numbers
  const prefix = Buffer.allocUnsafe(2);
  prefix.writeUInt16BE(rdata.byteLength);
  return Buffer.concat([prefix, rdata]);
}
