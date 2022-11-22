export function lengthPrefixRdata(rdata: Buffer): Buffer {
  const prefix = Buffer.allocUnsafe(2);
  prefix.writeUInt16BE(rdata.byteLength);
  return Buffer.concat([prefix, rdata]);
}
