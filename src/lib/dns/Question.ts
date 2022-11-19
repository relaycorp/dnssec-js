import { DnsClass } from './DnsClass';
import { serialiseName } from './name';
import { IANA_RR_TYPE_IDS, IANA_RR_TYPE_NAMES, IanaRrTypeNames } from './ianaRrTypes';
import { DnsError } from './DnsError';

export interface QuestionFields {
  readonly name: string;
  readonly type: number;
  readonly class: DnsClass;
}

export class Question {
  public readonly typeId: number;

  constructor(
    public readonly name: string,
    type: number | IanaRrTypeNames,
    public readonly class_: DnsClass,
  ) {
    const typeId: number | undefined = typeof type === 'number' ? type : IANA_RR_TYPE_IDS[type];
    if (typeId === undefined) {
      throw new DnsError(`RR type name "${type}" is not defined by IANA`);
    }
    this.typeId = typeId;
  }

  get key(): string {
    return `${this.name}/${this.typeId}`;
  }

  public getTypeName(): IanaRrTypeNames {
    const name = IANA_RR_TYPE_NAMES[this.typeId];
    if (!name) {
      throw new DnsError(`RR type id ${this.typeId} is not defined by IANA`);
    }
    return name;
  }

  public equals(differentQuestion: Question) {
    return (
      this.name === differentQuestion.name &&
      this.typeId === differentQuestion.typeId &&
      this.class_ === differentQuestion.class_
    );
  }

  public serialise(): Buffer {
    const nameSerialised = serialiseName(this.name);

    const serialisation = Buffer.allocUnsafe(nameSerialised.byteLength + 4);
    nameSerialised.copy(serialisation);
    serialisation.writeUInt16BE(this.typeId, nameSerialised.byteLength);
    serialisation.writeUInt16BE(this.class_, nameSerialised.byteLength + 2);
    return serialisation;
  }

  public shallowCopy(fields: Partial<QuestionFields>): Question {
    const newName = fields.name ?? this.name;
    const newType = fields.type ?? this.typeId;
    const newClass = fields.class ?? this.class_;
    return new Question(newName, newType, newClass);
  }
}
