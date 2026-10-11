# androidstudio.lambdawalker.vault.gradle

Gradle companion for [Signing Vault for Android Studio](https://github.com/lambdawalker/androidstudio.lambdawalker.vault). This repository builds independently; no Studio checkout or encrypted-vault library is required.

## Connect an Android project

Clone this repository. In the Android project's `settings.gradle.kts`, add the included build **inside** the existing `pluginManagement` block:

```kotlin
pluginManagement {
    includeBuild("C:/src/androidstudio.lambdawalker.vault.gradle")
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
```

In the application module's `build.gradle.kts`:

```kotlin
plugins {
    id("com.android.application")
    id("com.lambdawalker.vault.signing")
}
vaultSigning {
    identity.set("development")
    variant.set("debug")
}
```

Sync Gradle. In Android Studio, open **Tools → Signing Vault**, unlock, and use **Build with vault**. Normal builds do not receive vault credentials. This developer preview targets Windows 11, AGP 9.4.0, Gradle 9.8.1 and JDK 25. The plugin ID, DSL and wire protocol v1 are unchanged, including compatibility with Studio 0.1.0-dev.

## Development

Run `./gradlew test`. Windows CI exercises a real private named pipe against a test-only reference broker. `broker-protocol` contains bounded protocol parsing and keystore verification only; it cannot decrypt vaults. Its contract vectors are shared with the Studio repository. Changes to either protocol implementation must pass those vectors; incompatible changes require a new protocol version.

With Android SDK platform 37.2 and build tools 37.0.0 installed, run `python3 scripts/verify-android-fixture.py` for unsigned-locked, expected-certificate and rejected-password build checks.

## Migration

Replace the old included-build path pointing at `androidstudio.lambdawalker.vault` with this repository. Keep the existing plugin ID and `vaultSigning` block. Never place a PIN, recovery key or keystore password in Gradle files.
