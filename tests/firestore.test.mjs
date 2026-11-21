import {test, before, after} from 'node:test';
import {readFile} from 'node:fs/promises';
import {initializeTestEnvironment, assertSucceeds, assertFails} from '@firebase/rules-unit-testing';
import {doc, setDoc, getDoc, getDocs, collection, query, orderBy, limit, updateDoc, deleteDoc, serverTimestamp, Timestamp, runTransaction} from 'firebase/firestore';
import assert from 'node:assert/strict';
let env, alice, bob, guest;
const rc4 = {record_type:'eece455.stream-cipher.ciphertext', version:1, algorithm:'rc4', encoding:'hex', ciphertext:'ABCDEF', bit_length:24, key_encoding:'text'};
const entry = (record=rc4) => ({title:'Test encryption', createdAt:serverTimestamp(), record});
const ref = (db, id) => doc(db, 'users', 'alice', 'encryptions', id);
before(async () => {
  env = await initializeTestEnvironment({projectId:'demo-stream-cipher', firestore:{host:'127.0.0.1', port:8085, rules:await readFile('firestore.rules','utf8')}});
  alice=env.authenticatedContext('alice').firestore(); bob=env.authenticatedContext('bob').firestore(); guest=env.unauthenticatedContext().firestore();
});
after(async () => { await env?.cleanup(); });
test('owner can save and read a record', async () => {await assertSucceeds(setDoc(ref(alice,'own'),entry())); await assertSucceeds(getDoc(ref(alice,'own')));});
test('another account cannot read, list, create, modify, or delete owner history', async () => {
  await setDoc(ref(alice,'private'),entry());
  await assertFails(getDoc(ref(bob,'private')));
  await assertFails(getDocs(collection(bob,'users','alice','encryptions')));
  await assertFails(setDoc(ref(bob,'new'),entry()));
  await assertFails(updateDoc(ref(bob,'private'),{title:'Stolen'}));
  await assertFails(deleteDoc(ref(bob,'private')));
});
test('signed-out requests cannot access history', async () => {
  await assertFails(getDoc(ref(guest,'own'))); await assertFails(setDoc(ref(guest,'guest'),entry()));
});
test('keys, plaintext, and extra fields are rejected by rules', async () => {
  for (const field of ['key','plaintext','keystream','ownerId']) {
    await assertFails(setDoc(ref(alice,`extra-${field}`),{...entry(),[field]:'sensitive'}));
    await assertFails(setDoc(ref(alice,`nested-${field}`),entry({...rc4,[field]:'sensitive'})));
  }
});
test('title may change but original ciphertext and date are immutable', async () => {
  await setDoc(ref(alice,'rename'),entry());
  await assertSucceeds(updateDoc(ref(alice,'rename'),{title:'Renamed example'}));
  await assertFails(updateDoc(ref(alice,'rename'),{record:{...rc4,ciphertext:'123456'}}));
  await assertFails(updateDoc(ref(alice,'rename'),{createdAt:serverTimestamp()}));
});
test('timestamp must be assigned by the server', async () => { await assertFails(setDoc(ref(alice,'forged-date'),{...entry(),createdAt:Timestamp.fromMillis(1)})); });
test('invalid or oversized records and titles are rejected', async () => {
  for (const change of [{algorithm:'unknown'}, {ciphertext:'NOTHEX'}, {bit_length:23}, {ciphertext:'AB'.repeat(16385),bit_length:131080}]) await assertFails(setDoc(ref(alice,'bad-record'),entry({...rc4,...change})));
  for (const title of ['', 'a'.repeat(101)]) await assertFails(setDoc(ref(alice,'bad-title'),{...entry(),title}));
});
test('A5/1 records support non-byte-aligned data and both frame modes', async () => {
  const record={record_type:rc4.record_type,version:1,algorithm:'a51',encoding:'hex',ciphertext:'ABC0',bit_length:13,direction:'downlink',count_mode:'count',start_count:308,start_fn:null,segment_count:1,count_advance:'COUNT + 1 mod 2^22'};
  await assertSucceeds(setDoc(ref(alice,'a51-count'),entry(record)));
  await assertSucceeds(setDoc(ref(alice,'a51-fn'),entry({...record,count_mode:'fn',start_fn:123,count_advance:'FN + 1 mod 2715648'})));
  await assertFails(setDoc(ref(alice,'a51-invalid'),entry({...record,start_count:4194304})));
});
test('owner can query newest records with pagination limits', async () => {await assertSucceeds(getDocs(query(collection(alice,'users','alice','encryptions'),orderBy('createdAt','desc'),limit(25))));});
test('retrying a save transaction reuses the existing record', async () => {
  const target=ref(alice,'retry');
  const save=()=>runTransaction(alice,async transaction=>{if (!(await transaction.get(target)).exists()) transaction.set(target,entry());});
  await assertSucceeds(save());
  const first=(await getDoc(target)).data();
  await assertSucceeds(save());
  assert.equal((await getDoc(target)).data().createdAt.toMillis(),first.createdAt.toMillis());
});
test('owner can delete their own saved encryption', async () => {await setDoc(ref(alice,'delete'),entry()); await assertSucceeds(deleteDoc(ref(alice,'delete')));});
test('unrelated collections are closed', async () => {await assertFails(setDoc(doc(alice,'public','anything'),{message:'hello'}));});
