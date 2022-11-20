import { KeyObject, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { RRSigData } from '@leichtgewicht/dns-packet';
import { fromUnixTime, getUnixTime } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { normaliseName, serialiseName } from '../dns/name';
import { DnssecRecordData } from './DnssecRecordData';
import { RRSet } from '../dns/RRSet';
import { getNodejsHashAlgorithmFromDnssecAlgo } from '../utils/crypto/hashing';
import { getRrTypeId, IanaRrTypeName } from '../dns/ianaRrTypes';

export class RrsigData implements DnssecRecordData {
  static initFromPacket(packet: RRSigData): RrsigData {
    return new RrsigData(
      getRrTypeId(packet.typeCovered as IanaRrTypeName),
      packet.algorithm,
      packet.labels,
      packet.originalTTL,
      fromUnixTime(packet.expiration),
      fromUnixTime(packet.inception),
      packet.keyTag,
      packet.signersName,
      Buffer.from(packet.signature),
    );
  }

  public static generate(
    rrset: RRSet,
    signatureExpiry: Date,
    signatureInception: Date,
    signerPrivateKey: KeyObject,
    signerName: string,
    signerKeyTag: number,
    dnssecAlgorithm: DnssecAlgorithm,
  ): RrsigData {
    const rdataFirstPart = generateRdataFirstPart(
      signatureExpiry,
      signatureInception,
      signerKeyTag,
      dnssecAlgorithm,
      rrset,
    );
    const plaintext = Buffer.concat([rdataFirstPart, serialiseRrset(rrset)]);
    const signature = sign(plaintext, signerPrivateKey, dnssecAlgorithm);
    return new RrsigData(
      rrset.type,
      dnssecAlgorithm,
      countLabels(rrset.name),
      rrset.ttl,
      signatureExpiry,
      signatureInception,
      signerKeyTag,
      signerName,
      signature,
    );
  }

  public readonly signerName: string;

  constructor(
    public readonly type: number,
    public readonly algorithm: DnssecAlgorithm,
    public readonly labels: number,
    public readonly ttl: number,
    public readonly signatureExpiry: Date,
    public readonly signatureInception: Date,
    public readonly keyTag: number,
    signerName: string,
    public readonly signature: Buffer,
  ) {
    this.signerName = normaliseName(signerName);
  }

  public serialise(): Buffer {
    const signerNameBuffer = serialiseName(this.signerName);

    const serialisation = Buffer.allocUnsafe(
      18 + signerNameBuffer.byteLength + this.signature.byteLength,
    );

    serialisation.writeUInt16BE(this.type, 0);
    serialisation.writeUInt8(this.algorithm, 2);
    serialisation.writeUInt8(this.labels, 3);
    serialisation.writeUInt32BE(this.ttl, 4);
    serialisation.writeUInt32BE(getUnixTime(this.signatureExpiry), 8);
    serialisation.writeUInt32BE(getUnixTime(this.signatureInception), 12);
    serialisation.writeUInt16BE(this.keyTag, 16);
    signerNameBuffer.copy(serialisation, 18);
    this.signature.copy(serialisation, 18 + signerNameBuffer.byteLength);

    return serialisation;
  }

  public verifyRrset(rrset: RRSet, dnskeyPublicKey: KeyObject): boolean {
    if (rrset.type !== this.type) {
      return false;
    }

    if (rrset.ttl !== this.ttl) {
      return false;
    }

    const rrsetNameLabelCount = countLabels(rrset.name);
    if (rrsetNameLabelCount < this.labels) {
      return false;
    }

    const rdataFirstPart = generateRdataFirstPart(
      this.signatureExpiry,
      this.signatureInception,
      this.keyTag,
      this.algorithm,
      rrset,
    );
    const plaintext = Buffer.concat([rdataFirstPart, serialiseRrset(rrset)]);
    return verifySignature(plaintext, this.signature, dnskeyPublicKey, this.algorithm);
  }
}

// Calling this "first part" for lack of a better name, as RFC 4034 doesn't give it a name.
function generateRdataFirstPart(
  signatureExpiry: Date,
  signatureInception: Date,
  signerKeyTag: number,
  algorithm: DnssecAlgorithm,
  rrset: RRSet,
): Buffer {
  const partialRrsigRdata = Buffer.allocUnsafe(18);

  partialRrsigRdata.writeUInt16BE(rrset.type, 0);
  partialRrsigRdata.writeUInt8(algorithm, 2);
  partialRrsigRdata.writeUInt8(countLabels(rrset.name), 3);
  partialRrsigRdata.writeUInt32BE(rrset.ttl, 4);
  partialRrsigRdata.writeUInt32BE(getUnixTime(signatureExpiry), 8);
  partialRrsigRdata.writeUInt32BE(getUnixTime(signatureInception), 12);
  partialRrsigRdata.writeUInt16BE(signerKeyTag, 16);

  return partialRrsigRdata;
}

function serialiseRrset(rrset: RRSet): Buffer {
  return Buffer.concat(rrset.records.map((r) => r.serialise()));
}

function sign(plaintext: Buffer, privateKey: KeyObject, dnssecAlgorithm: DnssecAlgorithm): Buffer {
  const nodejsHashAlgorithm = getNodejsHashAlgorithmFromDnssecAlgo(dnssecAlgorithm);
  return cryptoSign(nodejsHashAlgorithm, plaintext, privateKey);
}

function verifySignature(
  plaintext: Buffer,
  signature: Buffer,
  publicKey: KeyObject,
  dnssecAlgorithm: DnssecAlgorithm,
): boolean {
  const nodejsHashAlgorithm = getNodejsHashAlgorithmFromDnssecAlgo(dnssecAlgorithm);
  return cryptoVerify(nodejsHashAlgorithm, plaintext, publicKey, signature);
}

function countLabels(name: string): number {
  const nameWithoutTrailingDot = name.replace(/\.$/, '');
  const labels = nameWithoutTrailingDot.split('.').filter((label) => label !== '*');
  return labels.length;
}
