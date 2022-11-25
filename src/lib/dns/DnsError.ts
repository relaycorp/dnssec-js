/**
 * DNS-related error.
 *
 * A violation of a DNSSEC-related RFC (e.g., RFC 1035), from which we can't or shouldn't recover.
 *
 * @see {DnssecError}
 */
export class DnsError extends Error {
  public override readonly name = 'DnsError';
}
