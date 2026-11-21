import {test} from 'node:test';
import assert from 'node:assert/strict';
import {historyRecord, historyDetails, encryptionDetails} from '../static/js/history_record.js';
const rc4 = {record_type: 'eece455.stream-cipher.ciphertext', version: 1, algorithm: 'rc4', encoding: 'hex', ciphertext: 'ABCDEF', bit_length: 24, key_encoding: 'text'};
const a51 = {...rc4, algorithm: 'a51', ciphertext: 'ABC0', bit_length: 13, direction: 'downlink', count_mode: 'count', start_count: 308, start_fn: null, segment_count: 1, count_advance: 'COUNT + 1 mod 2^22'};
delete a51.key_encoding;
test('ciphertext metadata remains separate from full experiment details', () => {
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

test('full details round trip with exact key, plaintext and keystream', () => {
  const details = {key:'Key',plaintext:'abc',input_format:'text',keystream:'123456'};
  assert.deepEqual(historyDetails({...details,password:'must not copy'},rc4),details);
  assert.equal(historyDetails(undefined,rc4),null);
  assert.throws(()=>historyDetails({...details,keystream:'12'},rc4));
  assert.throws(()=>historyDetails({...details,key:''},rc4));
});
test('snapshot captures request key and exact non-byte-aligned plaintext', () => {
  const result={algorithm:'a51',record:a51,plaintext:{binary:'1010101111000'},keystream:{hex:'1230'}};
  assert.deepEqual(encryptionDetails({key:'12 23 45 67 89 ab cd ef',input_format:'binary'},result),
    {key:'1223456789ABCDEF',plaintext:'1010101111000',input_format:'binary',keystream:'1230'});
});
