/**
 * DNS-related error.
 *
 * Most likely a violation of RFC 1035. Completely unrelated to DNSSEC.
 */
export class DnsError extends Error {}
