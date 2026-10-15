package dev.agentnest.core.nest

import dev.agentnest.core.Fixtures
import dev.agentnest.core.T
import dev.agentnest.core.link.LinkError
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.protocol.AgentKind
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.AgentStateSerializer
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.Ts
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import dev.agentnest.core.protocol.SessionState

class MoodResolverTest {
    private fun link(name: String, now: Instant): LinkState = when (name) {
        "connected" -> T.connected(now)
        "offline" -> LinkState.Offline
        "reconnecting" -> LinkState.Reconnecting(2, now.plusSeconds(4), LinkError.Unreachable)
        "pc_unreachable" -> LinkState.PcUnreachable(now.minusSeconds(60))
        "suspended" -> LinkState.Suspended(now.plusSeconds(3600))
        else -> error("fixture uses an unsupported link value: $name")
    }

    private fun agentKind(s: String) = AgentKind.entries.firstOrNull { it.wire == s } ?: AgentKind.UNKNOWN

    private fun stateOf(raw: String): AgentState =
        Codec.json.decodeFromString(AgentStateSerializer, JsonPrimitive(raw).toString())

    @Test
    fun `shared mood_priority fixture`() {
        val root = Fixtures.json("fixtures/mood_priority.json").jsonObject
        val cases = root["cases"]!!.jsonArray.map { it.jsonObject }
        assertTrue(cases.size >= 30, "fixture should have many cases")
        for (case in cases) {
            val name = case["name"]!!.jsonPrimitive.content
            val now = Instant.parse(case["now"]!!.jsonPrimitive.content)
            val rawStates = HashMap<String, String>()
            val sessions = case["sessions"]!!.jsonArray.map { it.jsonObject }.map { s ->
                val key = s["session_key"]!!.jsonPrimitive.content
                val raw = s["state"]!!.jsonPrimitive.content
                rawStates[key] = raw
                T.session(
                    key = key,
                    state = stateOf(raw),
                    agent = agentKind(s["agent_kind"]!!.jsonPrimitive.content),
                    since = Instant.parse(s["state_since"]!!.jsonPrimitive.content),
                    lastEvent = Instant.parse(s["last_event_at"]!!.jsonPrimitive.content),
                    ended = s["ended"]?.jsonPrimitive?.boolean ?: false,
                )
            }
            val linkName = case["link"]!!.jsonPrimitive.content
            val result = MoodResolver.resolve(MoodInput(link(linkName, now), sessions), null, now)
            val expect = case["expect"]!!.jsonObject

            assertEquals(expect["mood"]!!.jsonPrimitive.content, result.mood.wire, "$name: mood")
            val badge = expect["badge"].let { if (it == null || it is JsonNull) null else it.jsonPrimitive.content }
            assertEquals(badge, result.badge.symbol.ifEmpty { null }, "$name: badge")
            assertEquals(expect["badge_count"]!!.jsonPrimitive.int, result.badgeCount, "$name: badge_count")
            expect["variant"]?.jsonPrimitive?.contentOrNull?.let { variant ->
                assertEquals(variant, result.typingVariant?.name?.lowercase(), "$name: variant")
            }
            if (linkName == "connected") {
                val focusKey = expect["focus_session_key"].let { if (it == null || it is JsonNull) null else it.jsonPrimitive.content }
                assertEquals(focusKey, result.primarySessionKey, "$name: focus_session_key")
                val focusState = expect["focus_state"].let { if (it == null || it is JsonNull) null else it.jsonPrimitive.content }
                assertEquals(focusState, focusKey?.let(rawStates::get), "$name: fixture focus_state is the raw state of the focus session")
            }
        }
    }

    // ---- hysteresis -------------------------------------------------------------------------------

    private fun input(vararg sessions: SessionState, link: LinkState = T.connected()) = MoodInput(link, sessions.toList())

    private fun working(at: Instant = T.T0.minusSeconds(60)) = T.session("a", AgentState.WORKING, since = at)

    @Test
    fun `a mood is held for at least 1500 ms before dropping to a lower priority one`() {
        val t0 = T.T0
        val first = MoodResolver.resolve(input(T.session("a", AgentState.TESTING)), null, t0)
        assertEquals(KongiMood.TOOLS, first.mood)
        // 1.0 s later the session reports `working` (lower priority): still tools.
        val held = MoodResolver.resolve(input(working()), first, t0.plusMillis(1000))
        assertEquals(KongiMood.TOOLS, held.mood)
        assertEquals(first.since, held.since)
        // Exactly at the hold limit the switch happens.
        val switched = MoodResolver.resolve(input(working()), first, t0.plusMillis(1500))
        assertEquals(KongiMood.TYPING, switched.mood)
        assertEquals(TypingVariant.WEAK, switched.typingVariant)
        assertEquals(t0.plusMillis(1500), switched.since)
    }

    @Test
    fun `testing to writing_code flapping is damped`() {
        val t0 = T.T0
        var decision = MoodResolver.resolve(input(T.session("a", AgentState.TESTING)), null, t0)
        // Alternate states every 200 ms for one second: the face must not change.
        for (i in 1..5) {
            val state = if (i % 2 == 0) AgentState.TESTING else AgentState.WRITING_CODE
            decision = MoodResolver.resolve(input(T.session("a", state)), decision, t0.plusMillis(200L * i))
            assertEquals(KongiMood.TOOLS, decision.mood, "flap #$i")
        }
    }

    @Test
    fun `approval input and error moods take over immediately`() {
        val t0 = T.T0
        val base = MoodResolver.resolve(input(T.session("a", AgentState.TESTING)), null, t0)
        val approval = MoodResolver.resolve(
            input(T.session("a", AgentState.TESTING), T.session("b", AgentState.AWAITING_APPROVAL)), base, t0.plusMillis(10),
        )
        assertEquals(KongiMood.RAISE_HAND, approval.mood)
        assertEquals(Badge.EXCLAMATION, approval.badge)

        val working = MoodResolver.resolve(input(working()), null, t0)
        val error = MoodResolver.resolve(input(T.session("a", AgentState.ERROR)), working, t0.plusMillis(10))
        assertEquals(KongiMood.FLUSTERED, error.mood)

        val inputNeeded = MoodResolver.resolve(input(T.session("a", AgentState.AWAITING_INPUT)), working, t0.plusMillis(10))
        assertEquals(KongiMood.RAISE_HAND, inputNeeded.mood)
        assertEquals(Badge.QUESTION, inputNeeded.badge)
    }

    @Test
    fun `lower priority moods do not interrupt a recent higher one`() {
        val t0 = T.T0
        val error = MoodResolver.resolve(input(T.session("a", AgentState.ERROR)), null, t0)
        val after = MoodResolver.resolve(input(T.session("a", AgentState.IDLE)), error, t0.plusMillis(300))
        assertEquals(KongiMood.FLUSTERED, after.mood, "error cleared after 300 ms: still held")
        val later = MoodResolver.resolve(input(T.session("a", AgentState.IDLE)), after, t0.plusMillis(1500))
        assertEquals(KongiMood.BLINK_SLOW, later.mood)
    }

    @Test
    fun `flustered follows AgentState error only (no phone side timer)`() {
        val t0 = T.T0
        var decision = MoodResolver.resolve(input(T.session("a", AgentState.ERROR)), null, t0)
        // Sticky error stays for as long as the PC says `error`, far beyond any timer.
        for (minutes in listOf(1L, 5L, 30L)) {
            decision = MoodResolver.resolve(input(T.session("a", AgentState.ERROR)), decision, t0.plus(Duration.ofMinutes(minutes)))
            assertEquals(KongiMood.FLUSTERED, decision.mood)
        }
        // When the PC clears it, the mood leaves (the minimum hold has long passed).
        val cleared = MoodResolver.resolve(input(T.session("a", AgentState.WORKING)), decision, t0.plus(Duration.ofMinutes(31)))
        assertEquals(KongiMood.TYPING, cleared.mood)
    }

    @Test
    fun `celebrate lasts 4 seconds then returns to blink_slow`() {
        val done = T.T0
        val session = T.session("a", AgentState.COMPLETED, since = done)
        val first = MoodResolver.resolve(input(session), null, done.plusMillis(100))
        assertEquals(KongiMood.CELEBRATE, first.mood)
        val mid = MoodResolver.resolve(input(session), first, done.plusMillis(3900))
        assertEquals(KongiMood.CELEBRATE, mid.mood)
        val over = MoodResolver.resolve(input(session), mid, done.plusMillis(4000))
        assertEquals(KongiMood.BLINK_SLOW, over.mood)
    }

    @Test
    fun `new work interrupts a celebration immediately`() {
        val done = T.T0
        val celebrating = MoodResolver.resolve(input(T.session("a", AgentState.COMPLETED, since = done)), null, done.plusMillis(100))
        assertEquals(KongiMood.CELEBRATE, celebrating.mood)
        val next = MoodResolver.resolve(input(T.session("a", AgentState.WORKING, since = done.plusMillis(300))), celebrating, done.plusMillis(300))
        assertEquals(KongiMood.TYPING, next.mood)
    }

    @Test
    fun `link problems win at once and recovery returns to the session mood at once`() {
        val t0 = T.T0
        val working = MoodResolver.resolve(input(working()), null, t0)
        val down = MoodResolver.resolve(
            MoodInput(LinkState.Reconnecting(1, t0.plusSeconds(1), LinkError.Unreachable), listOf(working())),
            working, t0.plusMillis(50),
        )
        assertEquals(KongiMood.WORRIED, down.mood)
        val offline = MoodResolver.resolve(MoodInput(LinkState.Offline, listOf(working())), down, t0.plusMillis(60))
        assertEquals(KongiMood.SLEEPY, offline.mood)
        // Recovery 100 ms later: no 1.5 s wait.
        val back = MoodResolver.resolve(input(working()), offline, t0.plusMillis(160))
        assertEquals(KongiMood.TYPING, back.mood)
    }

    @Test
    fun `badge and headline refresh without resetting the hold timer`() {
        val t0 = T.T0
        val one = MoodResolver.resolve(input(T.session("a", AgentState.AWAITING_APPROVAL)), null, t0)
        val two = MoodResolver.resolve(
            input(T.session("a", AgentState.AWAITING_APPROVAL), T.session("b", AgentState.AWAITING_APPROVAL, agent = AgentKind.CODEX)),
            one, t0.plusMillis(700),
        )
        assertEquals(2, two.badgeCount)
        assertEquals(one.since, two.since)
    }

    @Test
    fun `headline names the agent when several sessions run`() {
        val sessions = arrayOf(
            T.session("claude_code:a", AgentState.TESTING, headline = "테스트를 돌리고 있어요"),
            T.session("codex:b", AgentState.IDLE, agent = AgentKind.CODEX, headline = "대기 중"),
        )
        val d = MoodResolver.resolve(input(*sessions), null, T.T0)
        assertEquals("Claude가 테스트를 돌리고 있어요 · 다른 1개는 대기 중", d.headline)
        val single = MoodResolver.resolve(input(sessions[0]), null, T.T0)
        assertEquals("테스트를 돌리고 있어요", single.headline)
    }

    @Test
    fun `unpaired and no session states`() {
        val unpaired = MoodResolver.resolve(MoodInput(LinkState.Unpaired, emptyList()), null, T.T0)
        assertEquals(KongiMood.BLINK_SLOW, unpaired.mood)
        assertNull(unpaired.primarySessionKey)
        val empty = MoodResolver.resolve(input(), null, T.T0)
        assertEquals(KongiMood.BLINK_SLOW, empty.mood)
    }

    @Test
    fun `clock skew is applied when aging a completed session`() {
        // The PC clock is 10 s ahead: state_since looks 10 s old on the PC timeline but is 0 s old locally.
        val phoneNow = T.T0
        val since = phoneNow.plusSeconds(10) // server timeline
        val session = T.session("a", AgentState.COMPLETED, since = since)
        val withSkew = MoodResolver.resolve(MoodInput(T.connected(), listOf(session), clockSkewMs = 10_000), null, phoneNow)
        assertEquals(KongiMood.CELEBRATE, withSkew.mood)
    }
}
