# IP Check

A cross-platform native app (iOS & Android) that fetches your public IPv4 and IPv6 addresses from [ipinfo.io](https://ipinfo.io).

Built with **Flutter** — compiles to fully native code on each platform.

---

## Features

- **Fetch IP Addresses** — hits `https://ipinfo.io/` (IPv4) and `https://v6.ipinfo.io/` (IPv6) in parallel
- **Show IP Addresses** — displays results in a dialog, also shown inline on the home screen
- **Secure token storage** — your ipinfo.io token is stored in the device's secure keychain (Keychain on iOS, EncryptedSharedPreferences on Android), never in plaintext
- **Long-press to copy** — tap and hold any IP address to copy it to the clipboard
- **Light/dark mode** — follows system preference

---

## Prerequisites

1. [Flutter SDK](https://docs.flutter.dev/get-started/install) ≥ 3.2.0
2. For iOS: Xcode + CocoaPods (`sudo gem install cocoapods`)
3. For Android: Android Studio + SDK

---

## Setup

```bash
# 1. Get dependencies
flutter pub get

# 2. iOS only — install pods
cd ios && pod install && cd ..

# 3. Run on a connected device or simulator
flutter run
```

---

## Project Structure

```
lib/
├── main.dart                  # App entry point, theme, provider setup
├── models/
│   ├── app_state.dart         # State management (token, fetch status, results)
│   └── ip_addresses.dart      # IpAddresses data model
├── services/
│   ├── ip_service.dart        # HTTP calls to ipinfo.io
│   └── token_service.dart     # Secure token persistence
└── screens/
    ├── home_screen.dart       # Main screen with the two buttons
    └── settings_screen.dart   # Token configuration screen
```

---

## Getting your ipinfo.io token

1. Sign up at [ipinfo.io](https://ipinfo.io/signup) (free tier available)
2. Copy your token from the dashboard
3. In the app, tap the ⚙️ icon → paste your token → Save

---

## Extending the app

The `IpAddresses` model and `AppState` are designed to be easy to build on. Future features (e.g. acting on the fetched addresses) can be added by:

1. Adding new methods to `AppState`
2. Adding new screens under `lib/screens/`
3. Adding new services under `lib/services/`
