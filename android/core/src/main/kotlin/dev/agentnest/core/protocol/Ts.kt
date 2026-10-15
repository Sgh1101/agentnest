package dev.agentnest.core.protocol

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeFormatterBuilder
import java.time.format.DateTimeParseException

/**
 * A wire timestamp (RFC 3339). Keeps the exact wire text so that decode -> encode is lossless,
 * and exposes the parsed [instant] for logic. Equality is by instant.
 */
@kotlinx.serialization.Serializable(with = TsSerializer::class)
class Ts private constructor(val instant: Instant, val raw: String) : Comparable<Ts> {
    override fun equals(other: Any?): Boolean = other is Ts && other.instant == instant
    override fun hashCode(): Int = instant.hashCode()
    override fun toString(): String = raw
    override fun compareTo(other: Ts): Int = instant.compareTo(other.instant)

    companion object {
        /** Always prints exactly 3 fractional digits, UTC, like the Rust side (`2026-10-15T09:12:33.120Z`). */
        private val MILLIS_UTC: DateTimeFormatter = DateTimeFormatterBuilder().appendInstant(3).toFormatter()

        /** Builds a timestamp from an instant using the canonical millisecond format. */
        fun of(instant: Instant): Ts = Ts(instant, MILLIS_UTC.format(instant))

        /** Parses an RFC 3339 timestamp; returns null when it is not parseable. */
        fun parseOrNull(text: String): Ts? = try {
            Ts(Instant.parse(text), text)
        } catch (_: DateTimeParseException) {
            null
        }

        /** Parses an RFC 3339 timestamp or throws [IllegalArgumentException]. */
        fun parse(text: String): Ts = requireNotNull(parseOrNull(text)) { "bad timestamp" }
    }
}

/** kotlinx.serialization adapter for [Ts]. Rejects unparseable timestamps. */
object TsSerializer : KSerializer<Ts> {
    override val descriptor = PrimitiveSerialDescriptor("Ts", PrimitiveKind.STRING)
    override fun deserialize(decoder: Decoder): Ts {
        val text = decoder.decodeString()
        return Ts.parseOrNull(text) ?: throw SerializationException("invalid RFC 3339 timestamp")
    }

    override fun serialize(encoder: Encoder, value: Ts) = encoder.encodeString(value.raw)
}
