import { AsnIntegerBigIntConverter, AsnProp, AsnPropTypes } from '@peculiar/asn1-schema';

/**
 * ASN.1-serialisable ECDSA signature.
 */
export class EcdsaSignature {
  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerBigIntConverter })
  public r!: bigint;

  @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerBigIntConverter })
  public s!: bigint;
}
