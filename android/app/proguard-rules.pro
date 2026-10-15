# R8 rules for the release build (debug builds are not minified).
# kotlinx.serialization, OkHttp and Okio ship their own consumer rules; only the optional TLS providers
# that OkHttp probes by reflection need -dontwarn.
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# Wire enums are mapped by their explicit `wire` strings (no reflection on names), but keep the stack
# traces of a crash readable.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Services / receivers are referenced from the manifest (AGP keeps them); nothing else is loaded by name.
