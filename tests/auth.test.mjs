// Run only with demo Firebase Auth and Firestore emulators.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {initializeApp, deleteApp} from 'firebase/app';
import {getAuth, connectAuthEmulator, createUserWithEmailAndPassword, sendEmailVerification, applyActionCode, reload, getIdToken, deleteUser} from 'firebase/auth';
import {getFirestore, connectFirestoreEmulator, doc, setDoc, getDoc, deleteDoc, serverTimestamp} from 'firebase/firestore';

test('email action unlocks private history only after verification and token refresh', async () => {
  const app = initializeApp({apiKey:'demo-key',projectId:'demo-stream-cipher'},'verification-test');
  const auth = getAuth(app);
  connectAuthEmulator(auth,'http://127.0.0.1:9099',{disableWarnings:true});
  const db = getFirestore(app);
  connectFirestoreEmulator(db,'127.0.0.1',8085);
  let user, target;
  try {
    ({user} = await createUserWithEmailAndPassword(auth,`verification-${Date.now()}@example.invalid`,'SampleOnly123!'));
    target = doc(db,'users',user.uid,'encryptions','sample');
    const record = {record_type:'eece455.stream-cipher.ciphertext',version:1,algorithm:'rc4',encoding:'hex',ciphertext:'BBF316E8D940AF0AD3',bit_length:72,key_encoding:'text'};
    const details = {key:'Key',plaintext:'Plaintext',input_format:'text',keystream:'EB9F7781B734CA72A7'};
    await assert.rejects(setDoc(target,{title:'Test',record,details,createdAt:serverTimestamp()}),{code:'permission-denied'});
    await sendEmailVerification(user);
    const messages = await (await fetch('http://127.0.0.1:9099/emulator/v1/projects/demo-stream-cipher/oobCodes')).json();
    const verification = messages.oobCodes.find(item=>item.email === user.email && item.requestType === 'VERIFY_EMAIL');
    assert.ok(verification);
    await assert.rejects(applyActionCode(auth,'invalid-code'));
    await applyActionCode(auth,verification.oobCode);
    await assert.rejects(applyActionCode(auth,verification.oobCode));
    await reload(user);
    await getIdToken(user,true);
    assert.equal(user.emailVerified,true);
    await setDoc(target,{title:'Test',record,details,createdAt:serverTimestamp()});
    assert.deepEqual((await getDoc(target)).data().details,details);
    await deleteDoc(target);
    await deleteUser(user);
  } finally { await deleteApp(app); }
});
