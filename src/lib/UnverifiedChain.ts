import { Question } from './dns/Question';
import { Message } from './dns/Message';
import { DnssecRecordType } from './DnssecRecordType';
import type { ChainVerificationResult, VerificationResult } from './results';
import { augmentFailureResult } from './results';
import { SecurityStatus } from './SecurityStatus';
import { Zone } from './Zone';
import type { DatePeriod } from './DatePeriod';
import { SignedRrSet } from './SignedRrSet';
import type { Resolver } from './Resolver';
import type { DnsClass } from './dns/ianaClasses';
import type { DsData } from './rdata/DsData';
import type { RrSet } from './dns/RrSet';

interface MessageByKey {
  readonly [key: string]: Message;
}

type FinalResolver = (question: Question) => Promise<Message>;

function getZonesInChain(zoneName: string, shouldIncludeRoot = true): readonly string[] {
  if (zoneName === '') {
    return shouldIncludeRoot ? ['.'] : [];
  }
  const parentZoneName = zoneName.replace(/^[^.]+\./u, '');
  const parentZones = getZonesInChain(parentZoneName, shouldIncludeRoot);
  return [...parentZones, zoneName];
}

async function retrieveZoneMessages(
  zoneNames: readonly string[],
  recordType: DnssecRecordType,
  classType: DnsClass,
  resolver: FinalResolver,
): Promise<MessageByKey> {
  const question = new Question('.', recordType, classType);
  return zoneNames.reduce(async (messages, zoneName) => {
    const message = await resolver(question.shallowCopy({ name: zoneName }));
    return { ...(await messages), [`${zoneName}/${recordType}`]: message };
  }, Promise.resolve({} as MessageByKey));
}

export class UnverifiedChain {
  public static initFromMessages(query: Question, messages: readonly Message[]): UnverifiedChain {
    const allMessages = messages.reduce<MessageByKey>((accumulator, message) => {
      if (message.questions.length === 0) {
        return accumulator;
      }
      const [question] = message.questions;
      const { key } = question;
      return { ...accumulator, [key]: message };
    }, {});
    const zoneNames = getZonesInChain(query.name);
    const messageByKey = zoneNames.reduce<MessageByKey>((accumulator, zoneName) => {
      const dsKey = `${zoneName}/${DnssecRecordType.DS}`;
      const dsMessage = zoneName === '.' ? null : allMessages[dsKey];
      const dnskeyKey = `${zoneName}/${DnssecRecordType.DNSKEY}`;
      return {
        ...accumulator,
        ...(dsMessage ? { [dsKey]: dsMessage } : {}),
        ...(dnskeyKey in allMessages ? { [dnskeyKey]: allMessages[dnskeyKey] } : {}),
      };
    }, {});

    if (!(query.key in allMessages)) {
      throw new Error(`At least one message must answer ${query.key}`);
    }

    return new UnverifiedChain(query, allMessages[query.key], messageByKey);
  }

  public static async retrieve(question: Question, resolver: Resolver): Promise<UnverifiedChain> {
    const finalResolver: FinalResolver = async (currentQuestion) => {
      const message = await resolver(currentQuestion);
      return message instanceof Message ? message : Message.deserialise(message);
    };
    const zoneNames = getZonesInChain(question.name);
    const dnskeyMessages = await retrieveZoneMessages(
      zoneNames,
      DnssecRecordType.DNSKEY,
      question.classId,
      finalResolver,
    );
    const dsMessages = await retrieveZoneMessages(
      zoneNames.slice(1), // Skip the root DS
      DnssecRecordType.DS,
      question.classId,
      finalResolver,
    );
    const zoneMessageByKey: MessageByKey = { ...dnskeyMessages, ...dsMessages };
    const response = await finalResolver(question);
    return new UnverifiedChain(question, response, zoneMessageByKey);
  }

  protected constructor(
    public readonly query: Question,
    public readonly response: Message,
    public readonly zoneMessageByKey: MessageByKey,
  ) {}

  public verify(datePeriod: DatePeriod, trustAnchors: readonly DsData[]): ChainVerificationResult {
    const rootZoneResult = this.getRootZone(trustAnchors, datePeriod);
    if (rootZoneResult.status !== SecurityStatus.SECURE) {
      return rootZoneResult;
    }

    const answers = SignedRrSet.initFromRecords(this.query, this.response.answers);
    const apexZoneName = answers.signerNames[0] ?? answers.rrset.name;
    const zonesResult = this.getZones(rootZoneResult.result, apexZoneName, datePeriod);
    if (zonesResult.status !== SecurityStatus.SECURE) {
      return zonesResult;
    }

    return this.verifyAnswers(answers, zonesResult.result, datePeriod);
  }

  protected getRootZone(
    trustAnchors: readonly DsData[],
    datePeriod: DatePeriod,
  ): VerificationResult<Zone> {
    const rootDnskeyKey = `./${DnssecRecordType.DNSKEY}`;
    if (!(rootDnskeyKey in this.zoneMessageByKey)) {
      return {
        status: SecurityStatus.INDETERMINATE,
        reasonChain: ['Cannot initialise root zone without a DNSKEY response'],
      };
    }
    const result = Zone.initRoot(this.zoneMessageByKey[rootDnskeyKey], trustAnchors, datePeriod);
    if (result.status !== SecurityStatus.SECURE) {
      return augmentFailureResult(result, 'Got invalid DNSKEY for root zone');
    }
    return result;
  }

  protected getZones(
    rootZone: Zone,
    apexZoneName: string,
    datePeriod: DatePeriod,
  ): VerificationResult<readonly Zone[]> {
    let zones = [rootZone];
    for (const zoneName of getZonesInChain(apexZoneName, false)) {
      const dnskeyKey = `${zoneName}/${DnssecRecordType.DNSKEY}`;
      if (!(dnskeyKey in this.zoneMessageByKey)) {
        return {
          status: SecurityStatus.INDETERMINATE,
          reasonChain: [`Cannot verify zone ${zoneName} without a DNSKEY response`],
        };
      }
      const dsKey = `${zoneName}/${DnssecRecordType.DS}`;
      if (!(dsKey in this.zoneMessageByKey)) {
        return {
          status: SecurityStatus.INDETERMINATE,
          reasonChain: [`Cannot verify zone ${zoneName} without a DS response`],
        };
      }
      const parent = zones[zones.length - 1];
      const zoneResult = parent.initChild(
        zoneName,
        this.zoneMessageByKey[dnskeyKey],
        this.zoneMessageByKey[dsKey],
        datePeriod,
      );
      if (zoneResult.status !== SecurityStatus.SECURE) {
        return augmentFailureResult(zoneResult, `Failed to verify zone ${zoneName}`);
      }
      const zone = zoneResult.result;

      zones = [...zones, zone];
    }
    return { status: SecurityStatus.SECURE, result: zones };
  }

  protected verifyAnswers(
    answers: SignedRrSet,
    zones: readonly Zone[],
    datePeriod: DatePeriod,
  ): VerificationResult<RrSet> {
    const apexZone = zones[zones.length - 1];
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
