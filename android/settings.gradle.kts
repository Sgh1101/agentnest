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
if (sdk != null && !skipAndroid) {
    include(":app")
    logger.lifecycle("[agentnest] Android SDK at $sdk -> including :app")
} else {
    logger.lifecycle("[agentnest] Android SDK not found (ANDROID_HOME / ANDROID_SDK_ROOT / local.properties sdk.dir) or agentnest.skipAndroid=true -> skipping :app")
}
