import { DsData } from '../rdata/DsData';
import { DnssecAlgorithm } from '../DnssecAlgorithm';
import { DigestType } from '../DigestType';

/**
 * Set of root Key-Signing Keys (KSKs) as published by IANA.
 *
 * @link https://www.iana.org/dnssec/files
 */
export const IANA_TRUST_ANCHORS: readonly DsData[] = [
  new DsData(
    20326,
    DnssecAlgorithm.RSASHA256,
    DigestType.SHA256,
    Buffer.from('E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D', 'hex'),
  ),
];
