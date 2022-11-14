import { Parser } from 'binary-parser';

import { Record } from './Record';
import { NAME_PARSER_OPTIONS } from './name';
import { Question } from './Question';

const QUESTION_PARSER = new Parser()
  .array('name', NAME_PARSER_OPTIONS)
  .uint16('type')
  .uint16('class');
const QUESTION_SET_PARSER = new Parser().array('questionSet', {
  formatter: (questiosnRaw: any) => questiosnRaw.map((questionRaw: any) => questionRaw.question),
  type: new Parser().nest('question', {
    formatter: (questionRaw: any) =>
      new Question(questionRaw.name, questionRaw.type, questionRaw.class),
    type: QUESTION_PARSER,
  }),
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
  .seek(2)
  .buffer('queryParams', { length: 2 })
  .uint16('qCount')
  .uint16('anCount')
  .seek(4) // Skip the rest of the header
  .choice('questions', {
    tag: 'qCount',
    choices: { 0: new Parser() }, // Skip actual parser when qCount=0
    defaultChoice: QUESTION_SET_PARSER,
    formatter: (questionSet) => questionSet?.questionSet ?? [],
  })
  .choice('answers', {
    tag: 'anCount',
    choices: { 0: new Parser() }, // Skip actual parser when anCount=0
    defaultChoice: ANSWER_SET_PARSER,
    formatter: (answerSet) => answerSet?.answerSet ?? [],
  });
