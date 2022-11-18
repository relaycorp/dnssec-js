import { DnskeyData } from '../../lib/rdata/DnskeyData';
import { deserialisePublicKey } from '../../lib/utils/crypto/keySerialisation';
import { DnssecAlgorithm } from '../../lib/DnssecAlgorithm';

const DNSSEC_ROOT_DNSKEY_SERIALISATION = Buffer.from(
  'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=',
  'base64',
);
/**
 * DNSSEC root key.
 *
 * As of 1st November 2022.
 *
 * @see {DNSSEC_ROOT_DNSKEY_KEY_TAG}
 */
export const DNSSEC_ROOT_DNSKEY_DATA = new DnskeyData(
  deserialisePublicKey(DNSSEC_ROOT_DNSKEY_SERIALISATION, DnssecAlgorithm.RSASHA256),
  3,
  DnssecAlgorithm.RSASHA256,
  { zoneKey: true, secureEntryPoint: true },
);
/**
 * Key tag for DNSSEC root key.
 *
 * @see {DNSSEC_ROOT_DNSKEY_DATA}
 */
export const DNSSEC_ROOT_DNSKEY_KEY_TAG = 20326;
