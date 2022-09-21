import { DSData } from './rdata/DSData';
import { DNSSECAlgorithm } from '../DNSSECAlgorithm';
import { DigestType } from '../DigestType';

/**
 * Set of root Key-Signing Keys (KSKs) as published by IANA.
 *
 * @link https://www.iana.org/dnssec/files
 */
export const ROOT_KSK_DS_SET: readonly DSData[] = [
  new DSData(
    20326,
    DNSSECAlgorithm.RSASHA256,
    DigestType.SHA256,
    Buffer.from('E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D', 'hex'),
  ),
];
