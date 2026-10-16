// Root build script.
//
// AGP is put on the ROOT classpath only when :app is included (Android SDK present, see settings.gradle.kts).
//  * Same classloader as the Kotlin Gradle plugin (declared below with `apply false`): with AGP 9's built-in
//    Kotlin, KGP must be able to load AGP classes, otherwise applying com.android.application fails with
//    "Could not create an instance of type KotlinAndroidTarget ... NoClassDefFoundError BaseVariant".
//  * Never declared unconditionally: on machines without Google Maven access (the local build box) resolving
//    AGP fails even when :app is not included (verified).
// :app therefore applies the plugin by id WITHOUT a version.
buildscript {
    if (System.getProperty("agentnest.includeApp") == "true") {
        repositories {
            google {
                content {
                    includeGroupByRegex("com\\.android.*")
                    includeGroupByRegex("com\\.google.*")
                    includeGroupByRegex("androidx.*")
                }
            }
            mavenCentral()
        }
        dependencies {
            // Keep in sync with `agp` in gradle/libs.versions.toml.
            classpath("com.android.tools.build:gradle:9.3.3")
        }
    }
}

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}
