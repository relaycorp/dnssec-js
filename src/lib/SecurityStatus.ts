/**
 * DNSSEC security status.
 *
 * See https://www.rfc-editor.org/rfc/rfc4035#section-4.3
 */
export enum SecurityStatus {
  SECURE = 'SECURE',
  INSECURE = 'INSECURE',
  BOGUS = 'BOGUS',
  INDETERMINATE = 'INDETERMINATE',
}
