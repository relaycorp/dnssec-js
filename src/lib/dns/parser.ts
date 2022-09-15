import { Parser } from 'binary-parser';
import { Record } from './Record';

const LABEL_PARSER = new Parser().uint8('labelLength').string('label', { length: 'labelLength' });
const NAME_PARSER_OPTIONS = {
  formatter: (labels: any) => labels.map((label: any) => label.label).join('.'),
  type: LABEL_PARSER,
  readUntil(lastItem: any): boolean {
    return lastItem.labelLength === 0;
  },
};
const QUESTION_PARSER = new Parser()
  .array('name', NAME_PARSER_OPTIONS)
  .uint16('type')
  .uint16('class');
const QUESTION_SET_PARSER = new Parser().array('questionSet', {
  type: new Parser().nest('question', { type: QUESTION_PARSER }),
  readUntil(): boolean {
    // @ts-ignore
    return this.questionSet.length === this.$parent.qCount;
  },
});
const ANSWER_PARSER = new Parser()
  .array('name', NAME_PARSER_OPTIONS)
  .uint16('type')
  .uint16('class')
  .uint32('ttl')
  .uint16('dataLength')
  .buffer('data', { length: 'dataLength', formatter: (i) => i.slice(1) });
const ANSWER_SET_PARSER = new Parser().array('answerSet', {
  formatter: (answersRaw) => answersRaw.map((answerRaw: any) => answerRaw.answer),
  type: new Parser().nest('answer', {
    type: ANSWER_PARSER,
    formatter(answerRaw: any): Record {
      return new Record(
        answerRaw.name,
        answerRaw.type,
        answerRaw.class,
        answerRaw.ttl,
        answerRaw.data,
      );
    },
  }),
  readUntil(): boolean {
    // @ts-ignore
    return this.answerSet.length === this.$parent.anCount;
  },
});
export const DNS_MESSAGE_PARSER = new Parser()
  .endianness('big')
  .useContextVars()
  .seek(4)
  .uint16('qCount')
  .uint16('anCount')
  .seek(4) // Skip the rest of the header
  .choice('question', {
    tag: 'qCount',
    choices: { 0: new Parser() }, // Skip actual parser when qCount=0
    defaultChoice: QUESTION_SET_PARSER,
  })
  .choice('answers', {
    tag: 'anCount',
    choices: { 0: new Parser() }, // Skip actual parser when anCount=0
    defaultChoice: ANSWER_SET_PARSER,
    formatter: (answerSet) => answerSet?.answerSet ?? [],
  });
