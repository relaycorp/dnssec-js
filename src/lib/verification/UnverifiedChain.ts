import { Question } from '../dns/Question';
import { Message } from '../dns/Message';
import { DnssecRecordType } from '../DnssecRecordType';
import { VerificationOptions } from './VerificationOptions';
import {
  augmentFailureResult,
  FailureResult,
  SuccessfulResult,
  VerificationResult,
} from './results';
import { RRSet } from '../dns/RRSet';
import { SecurityStatus } from './SecurityStatus';
import { Zone } from './Zone';
import { DatePeriod } from './DatePeriod';
import { IANA_TRUST_ANCHORS } from './IANA_TRUST_ANCHORS';
import { SignedRRSet } from './SignedRRSet';
import { Resolver } from './Resolver';
import { DnsClass } from '../dns/ianaClasses';
import { DsData } from '../rdata/DsData';

export type VerifiedChainResult = SuccessfulResult<RRSet>;
export type ChainVerificationResult = VerifiedChainResult | FailureResult;

interface MessageByKey {
  readonly [key: string]: Message;
}

type FinalResolver = (question: Question) => Promise<Message>;

export class UnverifiedChain {
  public static async retrieve(question: Question, resolver: Resolver): Promise<UnverifiedChain> {
    const finalResolver: FinalResolver = async (q) => {
      const message = await resolver(q);
      return message instanceof Message ? message : Message.deserialise(message);
    };
    const zoneNames = getZonesInChain(question.name);
    const dnskeyMessages = await retrieveZoneMessages(
      zoneNames,
      DnssecRecordType.DNSKEY,
      question.class_,
      finalResolver,
    );
    const dsMessages = await retrieveZoneMessages(
      zoneNames.slice(1), // Skip the root DS
      DnssecRecordType.DS,
      question.class_,
      finalResolver,
    );
    const zoneMessageByKey: MessageByKey = { ...dnskeyMessages, ...dsMessages };
    const response = await finalResolver(question);
    return new UnverifiedChain(question, response, zoneMessageByKey);
  }

  public static initFromMessages(query: Question, messages: readonly Message[]): UnverifiedChain {
    const allMessages = messages.reduce((acc, m) => {
      const question = m.questions[0];
      if (!question) {
        return acc;
      }
      const key = question.key;
      return { ...acc, [key]: m };
    }, {} as MessageByKey);
    const zoneNames = getZonesInChain(query.name);
    const messageByKey = zoneNames.reduce((acc, zoneName) => {
      const dsKey = `${zoneName}/${DnssecRecordType.DS}`;
      const dsMessage = zoneName === '.' ? null : allMessages[dsKey];
      const dnskeyKey = `${zoneName}/${DnssecRecordType.DNSKEY}`;
      const dnskeyMessage = allMessages[dnskeyKey];
      return {
        ...acc,
        ...(dsMessage ? { [dsKey]: dsMessage } : {}),
        ...(dnskeyMessage ? { [dnskeyKey]: dnskeyMessage } : {}),
      };
    }, {} as MessageByKey);

    const queryResponse = allMessages[query.key];
    if (!queryResponse) {
      throw new Error(`At least one message must answer ${query.key}`);
    }

    return new UnverifiedChain(query, queryResponse, messageByKey);
  }

  protected constructor(
    public readonly query: Question,
    public readonly response: Message,
    public readonly zoneMessageByKey: MessageByKey,
  ) {}

  public verify(options: Partial<VerificationOptions> = {}): ChainVerificationResult {
    const datePeriod = getDatePeriod(options.dateOrPeriod);

    const rootZoneResult = this.getRootZone(options.trustAnchors, datePeriod);
    if (rootZoneResult.status !== SecurityStatus.SECURE) {
      return rootZoneResult;
    }
    const rootZone = rootZoneResult.result;

    const intermediateZonesResult = this.getIntermediateZones(rootZone, datePeriod);
    if (intermediateZonesResult.status !== SecurityStatus.SECURE) {
      return intermediateZonesResult;
    }
    const intermediateZones = intermediateZonesResult.result;

    return this.verifyResponse(intermediateZones, datePeriod);
  }

  protected getRootZone(
    trustAnchors: readonly DsData[] | undefined,
    datePeriod: DatePeriod,
  ): VerificationResult<Zone> {
    const dnskeyMessage = this.zoneMessageByKey[`./${DnssecRecordType.DNSKEY}`];
    if (!dnskeyMessage) {
      return {
        status: SecurityStatus.INDETERMINATE,
        reasonChain: ['Cannot initialise root zone without a DNSKEY response'],
      };
    }
    const rootDsData = trustAnchors ?? IANA_TRUST_ANCHORS;
    const result = Zone.initRoot(dnskeyMessage, rootDsData, datePeriod);
    if (result.status !== SecurityStatus.SECURE) {
      return augmentFailureResult(result, 'Got invalid DNSKEY for root zone');
    }
    return result;
  }

  protected getIntermediateZones(
    rootZone: Zone,
    datePeriod: DatePeriod,
  ): VerificationResult<readonly Zone[]> {
    let zones = [rootZone];
    for (const zoneName of getZonesInChain(this.query.name, false)) {
      const zoneDnskeyMessage = this.zoneMessageByKey[`${zoneName}/${DnssecRecordType.DNSKEY}`];
      if (!zoneDnskeyMessage) {
        return {
          status: SecurityStatus.INDETERMINATE,
          reasonChain: [`Cannot verify zone ${zoneName} without a DNSKEY response`],
        };
      }
      const zoneDsMessage = this.zoneMessageByKey[`${zoneName}/${DnssecRecordType.DS}`];
      if (!zoneDsMessage) {
        return {
          status: SecurityStatus.INDETERMINATE,
          reasonChain: [`Cannot verify zone ${zoneName} without a DS response`],
        };
      }
      const parent = zones[zones.length - 1];
      const zoneResult = parent.initChild(zoneName, zoneDnskeyMessage, zoneDsMessage, datePeriod);
      if (zoneResult.status !== SecurityStatus.SECURE) {
        return augmentFailureResult(zoneResult, `Failed to verify zone ${zoneName}`);
      }
      const zone = zoneResult.result;

      zones = [...zones, zone];
    }
    return { status: SecurityStatus.SECURE, result: zones };
  }

  protected verifyResponse(
    intermediateZones: readonly Zone[],
    datePeriod: DatePeriod,
  ): VerificationResult<RRSet> {
    const apexZone = intermediateZones[intermediateZones.length - 1];
    const answers = SignedRRSet.initFromRecords(this.query, this.response.answers);
    if (!apexZone.verifyRrset(answers, datePeriod)) {
      return {
        status: SecurityStatus.BOGUS,
        reasonChain: ['Query response does not have a valid signature'],
      };
    }

    return {
      status: SecurityStatus.SECURE,
      result: answers.rrset,
    };
  }
}

function getDatePeriod(dateOrPeriod?: Date | DatePeriod): DatePeriod {
  const finalDateOrPeriod = dateOrPeriod ?? new Date();
  return finalDateOrPeriod instanceof DatePeriod
    ? finalDateOrPeriod
    : DatePeriod.init(finalDateOrPeriod, finalDateOrPeriod);
}

function getZonesInChain(zoneName: string, includeRoot: boolean = true): readonly string[] {
  if (zoneName === '') {
    return includeRoot ? ['.'] : [];
  }
  const parentZoneName = zoneName.replace(/^[^.]+\./, '');
  const parentZones = getZonesInChain(parentZoneName, includeRoot);
  return [...parentZones, zoneName];
}

async function retrieveZoneMessages(
  zoneNames: readonly string[],
  recordType: DnssecRecordType,
  class_: DnsClass,
  resolver: FinalResolver,
): Promise<MessageByKey> {
  const question = new Question('.', recordType, class_);
  return zoneNames.reduce(async (messages, zoneName) => {
    const message = await resolver(question.shallowCopy({ name: zoneName }));
    return { ...(await messages), [`${zoneName}/${recordType}`]: message };
  }, Promise.resolve({} as MessageByKey));
}
