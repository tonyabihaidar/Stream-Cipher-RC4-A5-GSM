import {test} from 'node:test';
import assert from 'node:assert/strict';
import {validPassword} from '../static/js/password_policy.js';
test('requires eight characters and every requested character class', () => {
  for (const invalid of ['Ab1!xyz','abcdefgh1!','ABCDEFGH1!','Abcdefgh!','Abcdefgh1','Abcdefg1 ', 'Abcdefg1+', null]) assert.equal(validPassword(invalid),false, String(invalid));
  for (const valid of ['Abcdef1!', 'A long password 1!', 'Abcdef1~']) assert.equal(validPassword(valid),true);
});
