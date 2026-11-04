// Firebase Messaging Service Worker
importScripts("https://www.gstatic.com/firebasejs/9.23.0/firebase-app-compat.js");
importScripts("https://www.gstatic.com/firebasejs/9.23.0/firebase-messaging-compat.js");

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

messaging.onBackgroundMessage((payload) => {
  const notificationTitle = payload.notification.title || 'Teer Online Result Alert';
  const notificationOptions = {
    body: payload.notification.body || 'Check the latest results now!',
    icon: '/icon.png'
  };
  self.registration.showNotification(notificationTitle, notificationOptions);
});
