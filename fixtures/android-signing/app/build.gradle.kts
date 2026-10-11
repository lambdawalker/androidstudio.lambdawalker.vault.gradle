plugins {
    id("com.android.application")
    id("com.lambdawalker.vault.signing")
}
android {
    namespace = "com.lambdawalker.vault.fixture"
    compileSdk { version = release(37) { minorApiLevel = 2 } }
    buildToolsVersion = "37.0.0"
    defaultConfig { applicationId = "com.lambdawalker.vault.fixture"; minSdk = 26; targetSdk = 37; versionCode = 1; versionName = "1" }
}
vaultSigning { identity.set("fixture"); variant.set("debug") }

// Disposable lifecycle probe ONLY. This fixture password is not a user credential.
// Never copy this block to a real app. Production credentials arrive over the broker.
providers.gradleProperty("spikeKeystore").orNull?.let { path ->
    androidComponents.finalizeDsl { dsl ->
        val signing = dsl.signingConfigs.create("disposableLifecycleProbe")
        signing.storeFile = file(path)
        signing.storeType = "PKCS12"
        signing.keyAlias = "fixture"
        signing.storePassword = if (providers.gradleProperty("spikeWrongPassword").isPresent) "intentionally-wrong" else "disposable-fixture-password"
        signing.keyPassword = "disposable-fixture-password"
        dsl.buildTypes.getByName("debug").signingConfig = signing
    }
}
