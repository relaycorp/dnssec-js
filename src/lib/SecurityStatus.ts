/* eslint-disable @typescript-eslint/prefer-enum-initializers */
/**
 * DNSSEC security status.
 *
 * See https://www.rfc-editor.org/rfc/rfc4035#section-4.3
 */
export enum SecurityStatus {
  SECURE,
  INSECURE,
  BOGUS,
  INDETERMINATE,
}
