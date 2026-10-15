package dev.agentnest.app.data

import dev.agentnest.core.nest.ApprovalHistory
import dev.agentnest.core.nest.ApprovalHistoryEntry
import dev.agentnest.core.protocol.ApprovalOutcome
import dev.agentnest.core.protocol.Delivery
import dev.agentnest.core.protocol.ObservedResult
import dev.agentnest.core.protocol.ResolvedBy
import dev.agentnest.core.protocol.RiskLevel
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.time.Instant

/**
 * Text form of the approval history (docs/android.md 2.3, "승인 기록"). Entries contain the card title, risk level and
 * outcome only: never the command, paths or diff (core's `ApprovalHistoryEntry` has no such field). Unknown enum
 * values decode to their `UNKNOWN` member; a damaged file decodes to an empty list.
 */
object ApprovalHistoryCodec {
    private val json = Json

    /** Serialises [history] (newest first, at most 50 entries). */
    fun encode(history: ApprovalHistory): String {
        val array = buildJsonArray {
            for (e in history.entries) {
                add(
                    buildJsonObject {
                        put("request_id", e.requestId)
                        put("session_key", e.sessionKey)
                        put("title", e.title)
                        put("tool_name", e.toolName)
                        put("agent_label", e.agentLabel)
                        put("project_name", e.projectName)
                        put("risk", e.riskLevel?.wire)
                        put("outcome", e.outcome.wire)
                        put("resolved_by", e.resolvedBy.wire)
                        put("resolved_at_ms", e.resolvedAt?.toEpochMilli())
                        put("delivery", e.delivery.wire)
                        put("observed", e.observedResult.wire)
                        put("message_ko", e.messageKo)
                    },
                )
            }
        }
        return json.encodeToString(JsonArray.serializer(), array)
    }

    /** Parses [text]; never throws. */
    fun decode(text: String?): List<ApprovalHistoryEntry> {
        if (text.isNullOrBlank()) return emptyList()
        return try {
            json.parseToJsonElement(text).jsonArray.mapNotNull { element -> entryOf(element.jsonObject) }.take(ApprovalHistory.MAX_ENTRIES)
        } catch (e: SerializationException) {
            emptyList()
        } catch (e: IllegalArgumentException) {
            emptyList()
        }
    }

    private fun entryOf(o: JsonObject): ApprovalHistoryEntry? {
        val requestId = str(o, "request_id") ?: return null
        return ApprovalHistoryEntry(
            requestId = requestId,
            sessionKey = str(o, "session_key").orEmpty(),
            title = str(o, "title").orEmpty(),
            toolName = str(o, "tool_name").orEmpty(),
            agentLabel = str(o, "agent_label").orEmpty(),
            projectName = str(o, "project_name").orEmpty(),
            riskLevel = str(o, "risk")?.let { wire -> RiskLevel.entries.firstOrNull { it != RiskLevel.UNKNOWN && it.wire == wire } ?: RiskLevel.UNKNOWN },
            outcome = ApprovalOutcome.entries.firstOrNull { it != ApprovalOutcome.UNKNOWN && it.wire == str(o, "outcome") } ?: ApprovalOutcome.UNKNOWN,
            resolvedBy = ResolvedBy.entries.firstOrNull { it != ResolvedBy.UNKNOWN && it.wire == str(o, "resolved_by") } ?: ResolvedBy.UNKNOWN,
            resolvedAt = (o["resolved_at_ms"] as? JsonPrimitive)?.longOrNull?.let { Instant.ofEpochMilli(it) },
            delivery = Delivery.entries.firstOrNull { it != Delivery.UNKNOWN && it.wire == str(o, "delivery") } ?: Delivery.UNKNOWN,
            observedResult = ObservedResult.entries.firstOrNull { it != ObservedResult.UNKNOWN && it.wire == str(o, "observed") } ?: ObservedResult.UNKNOWN,
            messageKo = str(o, "message_ko"),
        )
    }

    private fun str(o: JsonObject, key: String): String? {
        val value = o[key]
        if (value == null || value is JsonNull) return null
        return (value as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
    }
}
