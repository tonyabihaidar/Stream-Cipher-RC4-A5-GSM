// Bundle only the services this app uses. No analytics or administrative credentials.
export { initializeApp } from 'firebase/app';
export {
  getAuth, onAuthStateChanged, setPersistence, browserSessionPersistence,
  createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut, sendPasswordResetEmail,
  sendEmailVerification, reload, getIdToken,
} from 'firebase/auth';
export {
  getFirestore, collection, doc, setDoc, getDocs, updateDoc, deleteDoc,
  query, orderBy, limit, startAfter, serverTimestamp, runTransaction,
} from 'firebase/firestore';
