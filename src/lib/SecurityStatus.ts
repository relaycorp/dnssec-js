/**
 * DNSSEC security status.
 *
 * @link https://www.rfc-editor.org/rfc/rfc4035#section-4.3
 */
export enum SecurityStatus {
  SECURE,
  INSECURE,
  BOGUS,
  INDETERMINATE,
}
