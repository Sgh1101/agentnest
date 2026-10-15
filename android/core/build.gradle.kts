plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
    // No jvmToolchain(): the build box only has JDK 21 and foojay provisioning may be blocked.
    // Bytecode target is pinned to 17 regardless of the JDK running Gradle.
}

dependencies {
    api(libs.kotlinx.serialization.json)
    api(libs.kotlinx.coroutines.core)
    api(libs.okhttp) // OkHttpWsTransport exposes OkHttpClient in its public constructor
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.tls)
    testImplementation(libs.okhttp.mockwebserver3.junit5)
}

tasks.test {
    useJUnitPlatform()
    // Shared fixtures live in the repo-level protocol/ directory (single source of truth).
    systemProperty("agentnest.protocolDir", rootDir.parentFile.resolve("protocol").absolutePath)
}
