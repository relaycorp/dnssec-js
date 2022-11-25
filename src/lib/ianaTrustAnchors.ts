import { DsData } from './rdata/DsData.js';
import { DnssecAlgorithm } from './DnssecAlgorithm.js';
import { DigestType } from './DigestType.js';

/**
 * Set of root Key-Signing Keys (KSKs) as published by IANA.
 *
 * See https://www.iana.org/dnssec/files
 */
export const IANA_TRUST_ANCHORS: readonly DsData[] = [
  new DsData(
    // eslint-disable-next-line @typescript-eslint/no-magic-numbers
    20_326,
    DnssecAlgorithm.RSASHA256,
    DigestType.SHA256,
    Buffer.from('E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D', 'hex'),
  ),
];
