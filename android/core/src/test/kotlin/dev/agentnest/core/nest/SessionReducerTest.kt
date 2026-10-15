package dev.agentnest.core.nest

import dev.agentnest.core.Fixtures
import dev.agentnest.core.T
import dev.agentnest.core.protocol.Actor
import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.AgentKind
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.AgentStateSerializer
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.EventCategory
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.EventSource
import dev.agentnest.core.protocol.Severity
import dev.agentnest.core.protocol.Summary
import dev.agentnest.core.protocol.Ts
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Runs protocol/fixtures/state_transitions.json (shared with the Rust `state::SessionReducer`). */
class SessionReducerTest {
    private val base: Instant = Instant.parse("2026-10-15T00:00:00.000Z")

    private fun kindOf(wire: String): EventKind = EventKind.entries.first { it.wire == wire && it != EventKind.UNKNOWN }

    private fun eventOf(input: JsonObject, at: Instant): AgentEvent {
        val actor = input["actor"]?.jsonObject?.let {
            Actor(
                agentId = null,
                agentType = it["agent_type"]?.jsonPrimitive?.content,
                isSubagent = it["is_subagent"]?.jsonPrimitive?.boolean ?: false,
            )
        }
        val channel = input["channel"]?.jsonPrimitive?.content ?: "claude_code.hook.http"
        return AgentEvent(
            eventId = T.id(),
            seq = 1,
            ts = Ts.of(at),
            agentKind = AgentKind.CLAUDE_CODE,
            sessionKey = "claude_code:fixture",
            actor = actor,
            kind = kindOf(input["kind"]!!.jsonPrimitive.content),
            category = EventCategory.UNKNOWN,
            severity = Severity.INFO,
            summary = Summary(),
            detail = input["detail"]?.jsonObject,
            source = EventSource(channel),
        )
    }

    @Test
    fun `shared state_transitions fixture`() {
        val root = Fixtures.json("fixtures/state_transitions.json").jsonObject
        val cases = root["cases"]!!.jsonArray.map { it.jsonObject }
        assertTrue(cases.size >= 50, "fixture should hold the full transition table")
        for (case in cases) {
            val name = case["name"]!!.jsonPrimitive.content
            var derivation = SessionReducer.initial(base)
            for ((index, step) in case["steps"]!!.jsonArray.map { it.jsonObject }.withIndex()) {
                val at = base.plusMillis(step["t_ms"]!!.jsonPrimitive.long)
                val input = step["input"]
                if (input != null && input !is JsonNull) {
                    derivation = SessionReducer.reduce(derivation, eventOf(input.jsonObject, at), at)
                }
                val view = SessionReducer.view(derivation, at)
                val where = "$name step $index (t=${step["t_ms"]})"
                val expect = step["expect"]!!.jsonObject
                for ((key, expected) in expect) {
                    when (key) {
                        "state" -> assertEquals(
                            Codec.json.decodeFromString(AgentStateSerializer, JsonPrimitive(expected.jsonPrimitive.content).toString()),
                            view.state, "$where: state",
                        )
                        "stale" -> assertEquals(expected.jsonPrimitive.boolean, view.stale, "$where: stale")
                        "ended" -> assertEquals(expected.jsonPrimitive.boolean, view.ended, "$where: ended")
                        "turn_active" -> assertEquals(expected.jsonPrimitive.boolean, view.turnActive, "$where: turn_active")
                        "pending_approval_ids" -> assertEquals(
                            (expected as JsonArray).map { it.jsonPrimitive.content }, view.pendingApprovalIds, "$where: pending_approval_ids",
                        )
                        else -> error("$where: unknown expectation key $key")
                    }
                }
            }
        }
    }

    @Test
    fun `timelines events do not mutate state they are not meant to`() {
        val at = base
        var d = SessionReducer.initial(at)
        val noChange = listOf(EventKind.TOOL_COMPLETED, EventKind.COMMAND_COMPLETED, EventKind.TASK_CREATED, EventKind.SESSION_META_UPDATED, EventKind.UNKNOWN)
        for ((i, kind) in noChange.withIndex()) {
            val e = AgentEvent(T.id(), i.toLong(), Ts.of(at), AgentKind.CLAUDE_CODE, "k", null, null, kind, EventCategory.UNKNOWN, Severity.INFO, Summary(), null, null, EventSource(""), false)
            d = SessionReducer.reduce(d, e, at.plusSeconds(i.toLong()))
        }
        assertEquals(AgentState.IDLE, SessionReducer.view(d, at.plusSeconds(10)).state)
    }
}
