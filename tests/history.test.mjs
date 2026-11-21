import {test} from 'node:test';
import assert from 'node:assert/strict';
import {historyRecord} from '../static/js/history_record.js';
const rc4 = {record_type: 'eece455.stream-cipher.ciphertext', version: 1, algorithm: 'rc4', encoding: 'hex', ciphertext: 'ABCDEF', bit_length: 24, key_encoding: 'text'};
const a51 = {...rc4, algorithm: 'a51', ciphertext: 'ABC0', bit_length: 13, direction: 'downlink', count_mode: 'count', start_count: 308, start_fn: null, segment_count: 1, count_advance: 'COUNT + 1 mod 2^22'};
delete a51.key_encoding;
test('history excludes plaintext, keys, and keystream even when supplied', () => {
  assert.deepEqual(historyRecord({...rc4, key:'secret', plaintext:'private', keystream:'ABC', extra:{key:'secret'}}), rc4);
});
test('RC4 record round trips without changes', () => assert.deepEqual(historyRecord(rc4), rc4));
test('A5/1 preserves exact non-byte-aligned length and frame parameters', () => assert.deepEqual(historyRecord(a51), a51));
test('A5/1 frame-number records retain FN', () => {
  const record = {...a51, count_mode:'fn', start_fn:123, count_advance:'FN + 1 mod 2715648'};
  assert.deepEqual(historyRecord(record), record);
});
test('invalid history cannot be loaded into the form', () => {
  for (const change of [{algorithm:'unknown'}, {encoding:'base64'}, {ciphertext:'<script>'}, {ciphertext:'ABC'}, {bit_length:23}, {version:2}, {key_encoding:'unknown'}, {ciphertext:'AB'.repeat(16385)}]) {
    assert.throws(() => historyRecord({...rc4, ...change}));
  }
});
test('A5/1 rejects invalid frame metadata', () => {
  for (const change of [{direction:'both'}, {count_mode:'other'}, {start_count:4194304}, {start_count:-1}, {segment_count:2}, {count_mode:'fn', start_fn:null}]) assert.throws(() => historyRecord({...a51, ...change}));
});
