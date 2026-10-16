// CI-only module: it needs the Android SDK (ubuntu-latest has it; the local build box does not, see settings.gradle.kts).
// AGP 9 has built-in Kotlin: org.jetbrains.kotlin.android must NOT be applied (docs/android.md 1.1).
plugins {
    id("com.android.application") // version comes from the root buildscript classpath
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "dev.agentnest.app"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "dev.agentnest.app"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        compose = true
    }

    // AGP 9 defaults to Java 11; :core targets 17.
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    testOptions {
        unitTests {
            // android.* stubs return defaults instead of throwing in plain JVM tests (we avoid them anyway).
            isReturnDefaultValues = true
        }
    }
}

dependencies {
    implementation(project(":core"))

    val composeBom = platform(libs.androidx.compose.bom)
    implementation(composeBom)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.core)
    implementation(libs.androidx.fragment)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.biometric)
    implementation(libs.kotlinx.coroutines.android)
    // UNVERIFIED (Phase 0) P3: version 16.1.0 is taken from Google's sample; isolated behind the QrScanner interface.
    implementation(libs.play.code.scanner)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)

    // Instrumented Compose UI tests (screenshots, .github/workflows/android-screenshots.yml). Debug-only manifest
    // entry (ComponentActivity); nothing here ships in release.
    androidTestImplementation(composeBom)
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
