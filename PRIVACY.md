# SMS Shield — Privacy Policy & Architectural Constraints

User privacy is the foundational design pillar of SMS Shield. Unlike conventional SMS apps or invasive anti-spam tools, SMS Shield enforces strict limits on data access and data retention.

---

## 1. Non-Negotiable Privacy Rules

1. **No SMS Permissions**: The app does **NOT** request or use `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, or `WRITE_SMS`.
2. **Opt-In Notification Monitoring**: Notification access via Android's `NotificationListenerService` is strictly opt-in. Monitoring is disabled by default upon initial launch.
3. **Explicit Source Filtering**: The app reads notifications ONLY from an approved whitelist of SMS applications (e.g. Google Messages, Samsung Messages). Notifications from WhatsApp, Telegram, Signal, Banking apps, or email clients are completely ignored and dropped at the OS listener interface.
4. **No Raw SMS Storage**:
   - The backend database never stores full raw SMS content by default.
   - Only non-reversible cryptographic hashes (SHA-256), classification category, risk scores, and extracted domain names are stored.
5. **No Credential Harvesting**: OTPs, passwords, PINs, card numbers, and UPI PINs are scrubbed on-device prior to payload creation.
6. **No Silent Monitoring**: Whenever monitoring is active, the app displays its status transparently on the home dashboard. The user can toggle off monitoring instantly at any time.

---

## 2. Google Play Policy Alignment

- **SMS and Call Log Policy**: Because SMS Shield does not request `READ_SMS` or `RECEIVE_SMS`, it does not violate Google Play's SMS permissions restrictions.
- **Notification Listener Verification**: The application implements `NotificationListenerService` strictly for real-time security alerting on incoming messaging notifications, accompanied by prominent disclosure and an explicit user consent screen during onboarding.
- **Manual Scanning Alternative**: Users who do not wish to grant notification access retain 100% access to on-demand manual scanning via copy-paste and Android Sharesheet (`ACTION_SEND`).
