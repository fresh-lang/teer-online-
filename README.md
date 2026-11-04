# Teer Online - Advanced Realtime Admin & Gaming Platform

Ye project aapke Teer Online system ke 5 core operational controls ko seamlessly connect karta hai:

### Features & Implementation Overview:

1. **Market Schedule & Cutoff Timer:**
   - Admin panel se Shillong, Khanapara, aur Juwai ke FR / SR cutoff times aur result times edit karein.
   - User app me automatic reverse countdown timer chalta hai aur cutoff hote hi bet button lock ho jata hai.

2. **Live Risk & Bet Analytics:**
   - Real-time Market aur Round (FR/SR) filter.
   - Total Pool Amount vs. Maximum Liability (1:90 payout rate).
   - 00–99 Guti distribution table sorted by heaviest stake.
   - CRITICAL RISK badge agar kisi number par payout total pool se zyada ban raha ho.

3. **User Account Controls:**
   - 1-Click Block/Unblock toggle: Blocked user ko app me instant lock-out screen dikhti hai.
   - Instant Password/PIN Reset: Admin panel se direct kisi bhi user ka credential update karein.

4. **Deposit QR Code & UPI Changer:**
   - Admin panel se UPI ID aur Merchant Name change karte hi dynamic QR automatically generate hokar user app me update ho jata hai.
   - Direct WhatsApp helpline button integration.

5. **Notice Bar / Marquee Text Editor:**
   - Scrolling headline marquee editor with live on/off switch.

### Setup Instructions:
1. `js/firebase-config.js` me apna Firebase Realtime Database URL aur API Key dalein.
2. Firebase Database Rules me read/write permissions configure karein.
3. Hosting ke liye GitHub Pages ya Firebase Hosting par directly deploy karein.
