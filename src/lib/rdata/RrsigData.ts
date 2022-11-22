import { KeyObject, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { RRSigData } from '@leichtgewicht/dns-packet';
import { fromUnixTime, getUnixTime } from 'date-fns';

import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { countLabels, normaliseName, serialiseName } from '../dns/name';
import { DnssecRecordData } from './DnssecRecordData';
import { RRSet } from '../dns/RRSet';
import { getNodejsSignatureHashFromDnssecAlgo } from '../utils/crypto/hashing';
import { getRrTypeId, IanaRrTypeName } from '../dns/ianaRrTypes';
import {
  convertSignatureFromDnssec,
  convertSignatureToDnssec,
} from '../utils/crypto/signatureSerialisation';

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
    const plaintext = computeSignedData(
      signatureExpiry,
      signatureInception,
      signerKeyTag,
      dnssecAlgorithm,
      rrset,
      signerName,
      rrset.ttl,
    );
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

    const rrsetNameLabelCount = countLabels(rrset.name);
    if (rrsetNameLabelCount < this.labels) {
      return false;
    }

    const plaintext = computeSignedData(
      this.signatureExpiry,
      this.signatureInception,
      this.keyTag,
      this.algorithm,
      rrset,
      this.signerName,
      this.ttl,
    );
    return verifySignature(plaintext, this.signature, dnskeyPublicKey, this.algorithm);
  }
}

function computeSignedData(
  signatureExpiry: Date,
  signatureInception: Date,
  signerKeyTag: number,
  algorithm: DnssecAlgorithm,
  rrset: RRSet,
  signerName: string,
  ttl: number,
): Buffer {
  const rrsetSerialised = serialiseRrset(rrset, ttl);
  const signerNameSerialised = serialiseName(signerName);

  const signedData = Buffer.allocUnsafe(
    18 + signerNameSerialised.byteLength + rrsetSerialised.byteLength,
  );

  signedData.writeUInt16BE(rrset.type, 0);
  signedData.writeUInt8(algorithm, 2);
  signedData.writeUInt8(countLabels(rrset.name), 3);
  signedData.writeUInt32BE(ttl, 4);
  signedData.writeUInt32BE(getUnixTime(signatureExpiry), 8);
  signedData.writeUInt32BE(getUnixTime(signatureInception), 12);
  signedData.writeUInt16BE(signerKeyTag, 16);
  signerNameSerialised.copy(signedData, 18);

  rrsetSerialised.copy(signedData, 18 + signerNameSerialised.byteLength);

  return signedData;
}

function serialiseRrset(rrset: RRSet, ttl: number): Buffer {
  return Buffer.concat(rrset.records.map((r) => r.serialise(ttl)));
}

function sign(plaintext: Buffer, privateKey: KeyObject, dnssecAlgorithm: DnssecAlgorithm): Buffer {
  const nodejsHashAlgorithm = getNodejsSignatureHashFromDnssecAlgo(dnssecAlgorithm);
  const signature = cryptoSign(nodejsHashAlgorithm, plaintext, privateKey);
  return convertSignatureToDnssec(signature, dnssecAlgorithm);
}

function verifySignature(
  plaintext: Buffer,
  dnssecSignature: Buffer,
  publicKey: KeyObject,
  dnssecAlgorithm: DnssecAlgorithm,
): boolean {
  const signature = convertSignatureFromDnssec(dnssecSignature, dnssecAlgorithm);
  const nodejsHashAlgorithm = getNodejsSignatureHashFromDnssecAlgo(dnssecAlgorithm);
  return cryptoVerify(nodejsHashAlgorithm, plaintext, publicKey, signature);
}
