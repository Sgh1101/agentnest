// Root build script. Intentionally NO `alias(libs.plugins.android.application) apply false` here:
// declaring AGP at the root forces Gradle to resolve it from Google Maven even when :app is not
// included, which fails on machines without an Android SDK / Google Maven access (verified).
plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}
