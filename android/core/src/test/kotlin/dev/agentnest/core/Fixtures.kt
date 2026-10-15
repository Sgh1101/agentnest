package dev.agentnest.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.File
import java.math.BigDecimal

/** Locates the repo-level `protocol/` directory (the shared single source of truth for fixtures). */
object Fixtures {
    val protocolDir: File by lazy {
        val fromProperty = System.getProperty("agentnest.protocolDir")?.let(::File)
        val dir = fromProperty ?: File("../protocol").absoluteFile
        check(dir.isDirectory) { "protocol directory not found: $dir" }
        dir
    }

    fun file(relative: String): File = File(protocolDir, relative)

    fun text(relative: String): String = file(relative).readText(Charsets.UTF_8)

    fun json(relative: String): JsonElement = Json.parseToJsonElement(text(relative))

    /** All `*.json` files below [relative] (non recursive unless [recursive]), sorted by name. */
    fun jsonFiles(relative: String, recursive: Boolean = false): List<File> {
        val root = file(relative)
        if (!root.isDirectory) return emptyList()
        val sequence = if (recursive) root.walkTopDown() else root.listFiles()!!.asSequence()
        return sequence.filter { it.isFile && it.extension == "json" }.sortedBy { it.path }.toList()
    }

    /**
     * Removes `null` members (the Kotlin codec uses `explicitNulls = false`) so that wire JSON can be compared
     * semantically.
     */
    fun stripNulls(element: JsonElement): JsonElement = when (element) {
        is JsonObject -> JsonObject(element.filterValues { it !is JsonNull }.mapValues { stripNulls(it.value) })
        is JsonArray -> JsonArray(element.map(::stripNulls))
        else -> element
    }

    /** True when every member of [expected] is present in [actual] with an equal value (numbers compare numerically). */
    fun isSubset(expected: JsonElement, actual: JsonElement, path: String = "", problems: MutableList<String> = mutableListOf()): List<String> {
        when {
            expected is JsonObject && actual is JsonObject -> {
                for ((key, value) in expected) {
                    val other = actual[key]
                    if (other == null) problems += "$path/$key missing in re-encoded JSON" else isSubset(value, other, "$path/$key", problems)
                }
            }
            expected is JsonArray && actual is JsonArray -> {
                if (expected.size != actual.size) problems += "$path array size ${expected.size} != ${actual.size}"
                else expected.indices.forEach { isSubset(expected[it], actual[it], "$path[$it]", problems) }
            }
            expected is JsonPrimitive && actual is JsonPrimitive -> {
                val same = if (!expected.isString && !actual.isString && expected.content != "true" && expected.content != "false") {
                    BigDecimal(expected.content).compareTo(BigDecimal(actual.content)) == 0
                } else {
                    expected == actual
                }
                if (!same) problems += "$path differs: ${expected.content} vs ${actual.content}"
            }
            else -> problems += "$path type differs"
        }
        return problems
    }
}
