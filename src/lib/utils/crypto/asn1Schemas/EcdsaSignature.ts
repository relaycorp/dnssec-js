import { AsnIntegerBigIntConverter, AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';

/**
 * ASN.1-serialisable ECDSA signature.
 */
export class EcdsaSignature {
  // eslint-disable-next-line new-cap
  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerBigIntConverter })
  public rParam!: bigint;

  // eslint-disable-next-line new-cap
  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerBigIntConverter })
  public sParam!: bigint;
}
