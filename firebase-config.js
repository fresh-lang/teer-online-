// Real Firebase Project Credentials
const firebaseConfig = {
  apiKey: "AIzaSyCn-AKygN3yIvaXN9-TkDqoitoJRMKIDho",
  authDomain: "teer-online-e0d9d.firebaseapp.com",
  databaseURL: "https://teer-online-e0d9d-default-rtdb.firebaseio.com",
  projectId: "teer-online-e0d9d",
  storageBucket: "teer-online-e0d9d.firebasestorage.app",
  messagingSenderId: "178122817204",
  appId: "1:178122817204:web:98820cc4fa354bab0e21e1",
  measurementId: "G-0WV58DNLER"
};

// Initialize Firebase App
if (!firebase.apps.length) {
  firebase.initializeApp(firebaseConfig);
}

// Global Database and Auth Instances
const db = firebase.database();
const auth = firebase.auth();
