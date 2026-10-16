pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        gradlePluginPortal()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
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
}
rootProject.name = "agentnest-android"
include(":core")

fun androidSdkDir(): File? {
    val fromEnv = (System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT"))?.let(::File)
    if (fromEnv?.isDirectory == true) return fromEnv
    val lp = File(rootDir, "local.properties")
    if (lp.isFile) {
        val props = java.util.Properties().apply { lp.inputStream().use { load(it) } }
        props.getProperty("sdk.dir")?.let(::File)?.takeIf { it.isDirectory }?.let { return it }
    }
    return null
}
val skipAndroid = providers.gradleProperty("agentnest.skipAndroid").map { it.toBoolean() }.getOrElse(false)
val sdk = androidSdkDir()
val includeApp = sdk != null && !skipAndroid
// Read by the root build script: AGP must sit on the ROOT classpath next to the Kotlin Gradle plugin
// (same classloader), otherwise KGP cannot see AGP classes (NoClassDefFoundError BaseVariant).
System.setProperty("agentnest.includeApp", includeApp.toString())
if (includeApp) {
    include(":app")
    logger.lifecycle("[agentnest] Android SDK at $sdk -> including :app")
} else {
    logger.lifecycle("[agentnest] Android SDK not found (ANDROID_HOME / ANDROID_SDK_ROOT / local.properties sdk.dir) or agentnest.skipAndroid=true -> skipping :app")
}
