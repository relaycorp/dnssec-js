/**
 * DNSSEC-related error.
 *
 * A violation of a DNSSEC-related RFC, from which we can't or shouldn't recover.
 *
 * @see {DnsError}
 */
export class DnssecError extends Error {
  public override readonly name = 'DnssecError';
}
