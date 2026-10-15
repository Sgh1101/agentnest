package dev.agentnest.core.protocol

import dev.agentnest.core.Fixtures
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

/** Round-trips every shared example (protocol/examples) through the Kotlin codec. */
class ExamplesTest {
    private val topLevel = Fixtures.jsonFiles("examples")

    @Test
    fun `examples directory is present and non-trivial`() {
        assertTrue(topLevel.size >= 40, "expected the shared examples, found ${topLevel.size}")
    }

    @Test
    fun `every valid example decodes and re-encodes losslessly`() {
        val failures = mutableListOf<String>()
        for (file in topLevel) {
            val text = file.readText()
            val original = Codec.json.parseToJsonElement(text)
            val type = original.jsonObject["type"]?.jsonPrimitive?.content
            when (val result = Codec.decode(text)) {
                is DecodeResult.UnknownType -> {
                    if (type != result.type || !file.name.startsWith("unknown_type")) failures += "${file.name}: unexpected unknown type ${result.type}"
                }
                is DecodeResult.Invalid -> failures += "${file.name}: ${result.reason}"
                is DecodeResult.Decoded -> {
                    val encoded = Codec.encodeAny(result.message)
                    val reEncoded = Codec.json.parseToJsonElement(encoded)
                    val problems = Fixtures.isSubset(Fixtures.stripNulls(original), reEncoded)
                    if (problems.isNotEmpty()) failures += "${file.name}: ${problems.take(3)}"
                    // decode(encode(x)) == x
                    val again = Codec.decode(encoded)
                    if (again != result) failures += "${file.name}: decode(encode(x)) != x"
                }
            }
        }
        if (failures.isNotEmpty()) fail(failures.joinToString("\n"))
    }

    @Test
    fun `unknown message types are ignored without error`() {
        val result = Codec.decode(Fixtures.text("examples/unknown_type.1.json"))
        assertEquals(DecodeResult.UnknownType("future_message_type"), result)
    }

    @Test
    fun `forward compatible examples decode with UNKNOWN enums and fail-safe values`() {
        val request = decoded<ApprovalRequestMessage>("examples/forward_compat/approval_request.unknown_enums.json").payload
        assertEquals(RiskLevel.UNKNOWN, request.risk.level)
        assertEquals(RiskLevel.HIGH, request.risk.level.effective, "unknown risk level is treated as high, never lower")
        assertEquals(DetailsKind.UNKNOWN, request.details.kind)
        assertEquals(LocalPrompt.UNKNOWN, request.localPrompt)

        val session = decoded<SessionStateMessage>("examples/forward_compat/session_state.unknown_enums.json").payload
        assertEquals(AgentState.UNKNOWN, session.state)
        assertEquals(AgentState.WORKING, session.state.effective)
        assertEquals(RemoteApproval.UNKNOWN, session.remoteApproval)
        assertTrue(!session.remoteApproval.allowsRemoteApproval)

        val resolved = decoded<ApprovalResolvedMessage>("examples/forward_compat/approval_resolved.unknown_enums.json").payload
        assertEquals(ApprovalOutcome.UNKNOWN, resolved.outcome)
        assertEquals(ResolvedBy.UNKNOWN, resolved.resolvedBy)

        val event = decoded<EventMessage>("examples/forward_compat/event.unknown_enums.json").payload
        assertEquals(EventKind.UNKNOWN, event.kind)
    }

    @Test
    fun `model examples decode as their model type`() {
        for (file in Fixtures.jsonFiles("examples/model")) {
            val element = Codec.json.parseToJsonElement(file.readText())
            when {
                file.name.startsWith("agent_event.") -> Codec.json.decodeFromJsonElement(AgentEvent.serializer(), element)
                file.name.startsWith("approval_request.") -> Codec.json.decodeFromJsonElement(ApprovalRequest.serializer(), element)
                file.name.startsWith("session_state.") -> Codec.json.decodeFromJsonElement(SessionState.serializer(), element)
                file.name.startsWith("project_ref.") -> Codec.json.decodeFromJsonElement(Project.serializer(), element)
                file.name.startsWith("risk.") -> Codec.json.decodeFromJsonElement(RiskInfo.serializer(), element)
            }
        }
    }

    @Test
    fun `invalid examples that the Rust parser rejects are rejected by Kotlin too`() {
        val index = Fixtures.json("examples/invalid/_index.json").jsonObject["files"]!!.jsonObject
        // Kotlin readers are deliberately tolerant where protocol.md section 10 says so:
        //  - an unknown decision inside allowed_decisions is dropped (no button), see ApprovalRequest;
        //  - an unknown risk.extra_confirmation is treated as the strongest requirement;
        //  - an unknown welcome resync mode is treated as "snapshot" (the safe full resync).
        val tolerated = setOf("approval_request.1.json", "approval_request.11.json", "risk.1.json", "welcome.4.json")
        val accepted = mutableListOf<String>()
        for ((name, info) in index) {
            if (!info.jsonObject["rust_rejects"]!!.jsonPrimitive.boolean) continue
            if (name in tolerated) continue
            val file = Fixtures.jsonFiles("examples/invalid").first { it.name == name }
            if (file.name.startsWith("risk.")) continue // model-level fragment, not an envelope
            if (Codec.decode(file.readText()) is DecodeResult.Decoded) accepted += name
        }
        assertTrue(accepted.isEmpty(), "Kotlin accepted frames the protocol rejects: $accepted")
    }

    /**
     * Every invalid example must be rejected by the Kotlin codec unless it is on this list. The list holds only
     * (a) forward-compatibility tolerance required by protocol.md section 10 (unknown enum values), and
     * (b) pure JSON-Schema bounds (maxItems / maxLength / patterns / category-kind cross checks) that a reader that
     * merely renders PC-built messages does not need to enforce. A NEW invalid example that Kotlin accepts fails
     * this test so that a person decides which of the two it is.
     */
    @Test
    fun `invalid examples accepted by Kotlin are limited to documented tolerance cases`() {
        val tolerated = setOf(
            // (a) unknown enum values are tolerated (UNKNOWN fallbacks)
            "approval_request.1.json", "approval_request.6.json", "approval_request.11.json", "approval_resolved.1.json",
            "bye.1.json", "decision_result.1.json", "error.1.json", "event.7.json", "session_state.4.json", "welcome.4.json",
            // (b) schema bounds the reader does not enforce
            "approval_request.2.json", "approval_request.5.json", "approval_request.7.json", "approval_request.9.json",
            "approval_request.10.json", "approval_request.12.json", "approval_seen.1.json", "event.4.json", "event.5.json",
            "event.6.json", "event.8.json", "pair.5.json", "ping.4.json", "session_state.2.json", "session_state.3.json",
            "session_state.5.json", "snapshot.1.json", "snapshot.4.json", "snapshot_request.1.json",
        )
        val unexpected = Fixtures.jsonFiles("examples/invalid")
            .filter { it.name != "_index.json" && !it.name.startsWith("risk.") && !it.name.startsWith("agent_state.") }
            .filter { Codec.decode(it.readText()) is DecodeResult.Decoded && it.name !in tolerated && !it.name.startsWith("pairing_payload") }
            .map { it.name }
        assertTrue(unexpected.isEmpty(), "Kotlin accepts invalid examples that are not on the tolerance list: $unexpected")
    }

    @Test
    fun `invalid QR payload examples are rejected by the QR parser`() {
        for (file in Fixtures.jsonFiles("examples/invalid").filter { it.name.startsWith("pairing_payload.") }) {
            val encoded = dev.agentnest.core.crypto.B64.encodeUrl(file.readBytes())
            val result = dev.agentnest.core.protocol.QrPayload.parse(
                dev.agentnest.core.protocol.QrPayload.URI_PREFIX + encoded, java.time.Instant.parse("2026-10-15T09:00:00Z"),
            )
            assertIs<QrParseResult.Failure>(result, file.name)
        }
    }

    @Test
    fun `scope expanding decisions can never be built or encoded`() {
        val text = Fixtures.text("examples/invalid/decision.1.json")
        assertIs<DecodeResult.Invalid>(Codec.decode(text))
        val unknown = Fixtures.text("examples/invalid/approval_request.1.json")
        val decoded = Codec.decode(unknown)
        if (decoded is DecodeResult.Decoded) {
            val request = (decoded.message as ApprovalRequestMessage).payload
            assertTrue(request.allowedDecisions.none { it == Decision.UNKNOWN })
        }
    }

    private inline fun <reified T : WireMessage> decoded(relative: String): T {
        val result = Codec.decode(Fixtures.text(relative))
        assertIs<DecodeResult.Decoded>(result, "decode failed: $result")
        return assertIs<T>(result.message)
    }

}
