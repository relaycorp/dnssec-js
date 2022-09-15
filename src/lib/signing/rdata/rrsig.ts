import { createSign, KeyObject } from 'node:crypto';
import { getUnixTime } from 'date-fns';

import { RRSet } from '../../dns/RRSet';
import { getDNSSECAlgoFromKey } from '../utils';
import { serialiseName } from '../../dns/name';

export function serialiseRrsigData(
  rrset: RRSet,
  signatureExpiry: Date,
  signatureInception: Date,
  signerPrivateKey: KeyObject,
  signerName: string,
  signerKeyTag: number,
): Buffer {
  const signerNameBuffer = serialiseName(signerName);

  const rdataFirstPart = generateRdataFirstPart(
    signatureExpiry,
    signatureInception,
    signerName,
    signerKeyTag,
    signerPrivateKey,
    rrset,
  );
  const plaintext = Buffer.concat([rdataFirstPart, serialiseRrset(rrset)]);
  const signature = sign(plaintext, signerPrivateKey);

  return Buffer.concat([rdataFirstPart, signerNameBuffer, signature]);
}

// Calling this "first part" for lack of a better name, as RFC 4034 doesn't give it a name.
function generateRdataFirstPart(
  signatureExpiry: Date,
  signatureInception: Date,
  signerName: string,
  signerKeyTag: number,
  signerPrivateKey: KeyObject,
  rrset: RRSet,
): Buffer {
  const partialRrsigRdata = Buffer.allocUnsafe(18);

  partialRrsigRdata.writeUInt16BE(rrset.type, 0);
  partialRrsigRdata.writeUInt8(getDNSSECAlgoFromKey(signerPrivateKey), 2);
  partialRrsigRdata.writeUInt8(countLabels(signerName), 3);
  partialRrsigRdata.writeUInt32BE(rrset.ttl, 4);
  partialRrsigRdata.writeUInt32BE(getUnixTime(signatureExpiry), 8);
  partialRrsigRdata.writeUInt32BE(getUnixTime(signatureInception), 12);
  partialRrsigRdata.writeUInt16BE(signerKeyTag, 16);

  return partialRrsigRdata;
}

function serialiseRrset(rrset: RRSet): Buffer {
  return Buffer.concat(rrset.records.map((r) => r.serialise()));
}

function sign(plaintext: Buffer, privateKey: KeyObject): Buffer {
  const signer = createSign(privateKey.asymmetricKeyDetails!.hashAlgorithm!);
  signer.update(plaintext);
  signer.end();
  return signer.sign(privateKey);
}

function countLabels(name: string): number {
  const nameWithoutTrailingDot = name.replace(/\.$/, '');
  const labels = nameWithoutTrailingDot.split('.').filter((label) => label !== '*');
  return labels.length;
}
