/**
 * DNSSEC Algorithm Numbers.
 *
 * See https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
 */
export enum DnssecAlgorithm {
  RSASHA1 = 5,
  RSASHA256 = 8,
  RSASHA512 = 10,
  ECDSAP256SHA256 = 13,
  ECDSAP384SHA384 = 14,
  ED25519 = 15,
  ED448 = 16,
}
