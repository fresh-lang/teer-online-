// Firebase Messaging service worker. Replace the config with firebase-config.json values.
importScripts("https://www.gstatic.com/firebasejs/10.13.2/firebase-app-compat.js");
importScripts("https://www.gstatic.com/firebasejs/10.13.2/firebase-messaging-compat.js");
firebase.initializeApp({
  apiKey: "AIzaSyCn-AKygN3yIvaXN9-TkDqoitoJRMKIDho",
  authDomain: "teer-online-e0d9d.firebaseapp.com",
  databaseURL: "https://teer-online-e0d9d-default-rtdb.firebaseio.com",
  projectId: "teer-online-e0d9d",
  storageBucket: "teer-online-e0d9d.firebasestorage.app",
  messagingSenderId: "178122817204",
  appId: "1:178122817204:web:98820cc4fa354bab0e21e1"
});
const messaging = firebase.messaging();
messaging.onBackgroundMessage(payload => {
  const n = payload.notification || {};
  self.registration.showNotification(n.title || "Teer Online", {
    body: n.body || "New result update",
    icon: "/icon-192.png",
    data: payload.data || {}
  });
});
