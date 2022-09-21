/**
 * DNSSEC Delegation Signer (DS) Resource Record (RR) Type Digest Algorithms.
 *
 * @link https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
 *
 * GOST R 34.11-94 is unsupported because Node.js doesn't support it as of this writing.
 */
export enum DigestType {
  SHA1 = 1,
  SHA256 = 2,
  SHA384 = 4,
}
