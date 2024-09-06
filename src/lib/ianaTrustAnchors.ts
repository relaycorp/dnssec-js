import { DsData } from './records/DsData.js';
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
  new DsData(
    // eslint-disable-next-line @typescript-eslint/no-magic-numbers
    38_696,
    DnssecAlgorithm.RSASHA256,
    DigestType.SHA256,
    Buffer.from('683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16', 'hex'),
  ),
];
