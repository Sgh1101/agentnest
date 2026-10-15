package dev.agentnest.core.nest

import dev.agentnest.core.T
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.protocol.AckMessage
import dev.agentnest.core.protocol.AdapterStatusKind
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.ApprovalOutcome
import dev.agentnest.core.protocol.ClientMessage
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.DecisionResultReason
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.ObservedResult
import dev.agentnest.core.protocol.Resync
import dev.agentnest.core.protocol.ResyncMode
import dev.agentnest.core.protocol.ServerMessage
import dev.agentnest.core.protocol.Severity
import dev.agentnest.core.protocol.SnapshotRequestMessage
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NestReducerTest {
    private val reducer = NestReducer { T.id() }
    private val now = T.T0

    private fun start(link: LinkState = T.connected()): NestState = reducer.initial(now, link)

    private fun NestState.apply(message: ServerMessage, at: Instant = now): Pair<NestState, List<ClientMessage>> =
        reducer.reduce(this, message, at).let { it.state to it.outbound }

    /** A connected state that already holds a snapshot at [seq]. */
    private fun synced(seq: Long = 100, sessions: List<dev.agentnest.core.protocol.SessionState> = emptyList()): NestState {
        var s = start()
        s = s.apply(T.welcome()).first
        s = s.apply(T.snapshot(seq, sessions)).first
        return s
    }

    // ---- snapshot ---------------------------------------------------------------------------------

    @Test
    fun `snapshot replaces sessions and never merges`() {
        var s = synced(100, listOf(T.session("a", AgentState.WORKING), T.session("b", AgentState.TESTING)))
        assertEquals(setOf("a", "b"), s.sessions.keys)
        s = s.apply(T.snapshot(150, listOf(T.session("c", AgentState.IDLE)))).first
        assertEquals(setOf("c"), s.sessions.keys, "sessions a and b vanished: snapshot replaces")
        assertEquals(150, s.lastSeq)
        assertEquals(KongiMood.BLINK_SLOW, s.mood.mood)
    }

    @Test
    fun `snapshot replaces pending approvals and closes cards the PC no longer lists`() {
        val keep = T.request(id = "ar_keep")
        val gone = T.request(id = "ar_gone")
        var s = synced()
        s = s.apply(T.snapshot(110, approvals = listOf(keep, gone))).first
        assertEquals(setOf("ar_keep", "ar_gone"), s.approvals.keys)
        s = s.apply(T.snapshot(120, approvals = listOf(keep))).first
        assertEquals(setOf("ar_keep"), s.approvals.keys)
        val closed = assertNotNull(s.history.find("ar_gone"))
        assertEquals(ApprovalOutcome.UNKNOWN, closed.outcome, "shown as '처리됨'")
    }

    @Test
    fun `snapshot ids without a body stay as loading placeholders and follow-up frames fill them in`() {
        val full = T.request(id = "ar_full")
        val late = T.request(id = "ar_late", ttlSeconds = 100)
        var s = synced(100)
        // The snapshot lists both ids but only carries one body (truncation step 5).
        val (afterSnapshot, acks) = s.apply(T.snapshot(200, approvals = listOf(full), ids = listOf("ar_full", "ar_late")))
        s = afterSnapshot
        assertTrue(s.approvals.getValue("ar_late").isLoading, "buttons must stay disabled")
        assertEquals(false, s.approvals.getValue("ar_full").isLoading)
        val ack = assertIs<AckMessage>(acks.single())
        assertEquals(listOf("ar_full"), ack.payload.approvalIds)

        // Follow-up frame carries its ORIGINAL (older) seq: it must not be dropped as a duplicate.
        val (afterFollowUp, followAck) = s.apply(T.approvalMsg(150, late))
        assertEquals(false, afterFollowUp.approvals.getValue("ar_late").isLoading)
        assertEquals(200, afterFollowUp.lastSeq, "a follow-up never moves lastSeq backwards")
        assertEquals(listOf("ar_late"), assertIs<AckMessage>(followAck.single()).payload.approvalIds)
    }

    @Test
    fun `a loading card that is not in the next snapshot id list is cleaned up`() {
        var s = synced(100)
        s = s.apply(T.snapshot(200, ids = listOf("ar_ghost"))).first
        assertTrue(s.approvals.getValue("ar_ghost").isLoading)
        s = s.apply(T.snapshot(210, ids = emptyList())).first
        assertTrue(s.approvals.isEmpty())
    }

    @Test
    fun `a card known with a body keeps it when a later snapshot only lists its id`() {
        val req = T.request(id = "ar_one")
        var s = synced(100)
        s = s.apply(T.snapshot(110, approvals = listOf(req))).first
        s = s.apply(T.snapshot(120, ids = listOf("ar_one"))).first
        assertEquals(false, s.approvals.getValue("ar_one").isLoading)
    }

    @Test
    fun `snapshot never resurrects an expired approval`() {
        val expired = T.request(id = "ar_old", created = now.minusSeconds(300), ttlSeconds = 120)
        val s = synced().apply(T.snapshot(300, approvals = listOf(expired))).first
        assertTrue(s.approvals.isEmpty())
    }

    @Test
    fun `snapshot merges recent events by seq and replaces recent errors`() {
        var s = synced()
        val e1 = T.event(101)
        val e2 = T.event(102)
        s = s.apply(T.snapshot(102, events = listOf(e1, e2))).first
        s = s.apply(T.snapshot(103, events = listOf(e2, T.event(103)))).first
        assertEquals(listOf(101L, 102L, 103L), s.recentEvents.map { it.seq })
    }

    @Test
    fun `snapshot seq may be lower than lastSeq after a PC database reset`() {
        var s = synced(500)
        s = s.apply(T.snapshot(5, listOf(T.session("a", AgentState.IDLE)))).first
        assertEquals(5, s.lastSeq)
        s = s.apply(T.sessionMsg(6, T.session("a", AgentState.WORKING))).first
        assertEquals(AgentState.WORKING, s.sessions.getValue("a").state)
    }

    // ---- sequence / resync ------------------------------------------------------------------------

    @Test
    fun `consecutive seq applies and advances lastSeq`() {
        var s = synced(100)
        s = s.apply(T.sessionMsg(101, T.session("a", AgentState.WORKING))).first
        s = s.apply(T.sessionMsg(102, T.session("a", AgentState.TESTING))).first
        assertEquals(102, s.lastSeq)
        assertEquals(AgentState.TESTING, s.sessions.getValue("a").state)
    }

    @Test
    fun `duplicate seq is ignored`() {
        var s = synced(100)
        s = s.apply(T.sessionMsg(101, T.session("a", AgentState.WORKING))).first
        val again = s.apply(T.sessionMsg(101, T.session("a", AgentState.ERROR)))
        assertEquals(s, again.first)
        assertTrue(again.second.isEmpty())
    }

    @Test
    fun `a seq gap requests exactly one snapshot and drops messages until it arrives`() {
        var s = synced(100)
        val (afterGap, out) = s.apply(T.sessionMsg(105, T.session("a", AgentState.WORKING)))
        s = afterGap
        assertTrue(s.resync.awaitingSnapshot)
        assertEquals(100, s.lastSeq, "the gapped message is not applied")
        assertTrue(s.sessions.isEmpty())
        val request = assertIs<SnapshotRequestMessage>(out.single())
        assertEquals("seq_gap", request.payload.reason)

        // More traffic while waiting: dropped silently, no second request.
        val (afterMore, outMore) = s.apply(T.sessionMsg(106, T.session("a", AgentState.TESTING)))
        assertTrue(outMore.isEmpty())
        assertTrue(afterMore.sessions.isEmpty())

        // The snapshot clears the wait; later seqs apply again.
        s = afterMore.apply(T.snapshot(106, listOf(T.session("a", AgentState.TESTING)))).first
        assertFalse(s.resync.awaitingSnapshot)
        s = s.apply(T.sessionMsg(107, T.session("a", AgentState.IDLE))).first
        assertEquals(AgentState.IDLE, s.sessions.getValue("a").state)
        assertEquals(107, s.lastSeq)
    }

    @Test
    fun `a stuck snapshot request is retried by tick after 10 seconds`() {
        var s = synced(100)
        s = s.apply(T.sessionMsg(105, T.session("a", AgentState.WORKING))).first
        val early = reducer.tick(s, now.plusSeconds(9))
        assertTrue(early.outbound.isEmpty())
        val retry = reducer.tick(early.state, now.plusSeconds(10))
        assertIs<SnapshotRequestMessage>(retry.outbound.single())
        val noSpam = reducer.tick(retry.state, now.plusSeconds(11))
        assertTrue(noSpam.outbound.isEmpty())
    }

    @Test
    fun `welcome resync replay continuing from lastSeq needs no snapshot`() {
        var s = synced(1830)
        s = s.apply(T.welcome(resync = Resync(ResyncMode.REPLAY, 1831, 1842))).first
        assertFalse(s.resync.awaitingSnapshot)
        s = s.apply(T.sessionMsg(1831, T.session("a", AgentState.WORKING))).first
        assertEquals(1831, s.lastSeq)
    }

    @Test
    fun `welcome resync replay that cannot continue triggers a snapshot request`() {
        val s = synced(1000)
        val (next, out) = s.apply(T.welcome(resync = Resync(ResyncMode.REPLAY, 1500, 1600)))
        assertTrue(next.resync.awaitingSnapshot)
        assertIs<SnapshotRequestMessage>(out.single())
    }

    @Test
    fun `welcome resync snapshot waits for the snapshot and drops stray messages`() {
        var s = start()
        s = s.apply(T.welcome(resync = Resync(ResyncMode.SNAPSHOT))).first
        assertTrue(s.resync.awaitingSnapshot)
        val (dropped, out) = s.apply(T.sessionMsg(1, T.session("a", AgentState.WORKING)))
        assertTrue(dropped.sessions.isEmpty())
        assertTrue(out.isEmpty())
        s = dropped.apply(T.snapshot(40)).first
        assertFalse(s.resync.awaitingSnapshot)
        assertEquals(40, s.lastSeq)
    }

    @Test
    fun `welcome resync none and unknown`() {
        var s = synced(10).apply(T.welcome(resync = Resync(ResyncMode.NONE))).first
        assertFalse(s.resync.awaitingSnapshot)
        s = synced(10).apply(T.welcome(resync = Resync(ResyncMode.UNKNOWN))).first
        assertTrue(s.resync.awaitingSnapshot, "an unknown resync mode falls back to a full snapshot")
    }

    @Test
    fun `messages without seq are not subject to the sequence check`() {
        var s = synced(100)
        s = s.apply(T.decisionResult("ar_x", true, DecisionResultReason.APPLIED)).first
        assertEquals(100, s.lastSeq)
        assertNotNull(s.lastDecisionResult)
    }

    // ---- approvals --------------------------------------------------------------------------------

    @Test
    fun `approval request is added and acked immediately`() {
        val req = T.request(id = "ar_1")
        val (s, out) = synced(100).apply(T.approvalMsg(101, req))
        assertNotNull(s.approvals["ar_1"])
        assertEquals(listOf("ar_1"), assertIs<AckMessage>(out.single()).payload.approvalIds)
        assertEquals(1, s.pendingCards(now).size)
    }

    @Test
    fun `resent approval request is acked again but not duplicated`() {
        val req = T.request(id = "ar_1")
        var s = synced(100).apply(T.approvalMsg(101, req)).first
        val (again, out) = s.apply(T.approvalMsg(101, req))
        assertEquals(s.approvals, again.approvals)
        assertEquals(listOf("ar_1"), assertIs<AckMessage>(out.single()).payload.approvalIds)
        s = again
        assertEquals(1, s.approvals.size)
    }

    @Test
    fun `an expired approval request is never created`() {
        val expired = T.request(id = "ar_old", created = now.minusSeconds(200), ttlSeconds = 120)
        val (s, out) = synced(100).apply(T.approvalMsg(101, expired))
        assertTrue(s.approvals.isEmpty())
        assertTrue(out.isEmpty())
        assertEquals(101, s.lastSeq, "the seq is still consumed")
    }

    @Test
    fun `an expired card stops being pending immediately and is closed by tick after a grace period`() {
        val req = T.request(id = "ar_1", ttlSeconds = 120)
        var s = synced(100).apply(T.approvalMsg(101, req)).first
        val atExpiry = now.plusSeconds(120)
        assertTrue(s.pendingCards(atExpiry).isEmpty(), "expired cards are never pending/actionable")
        s = reducer.tick(s, atExpiry).state
        assertNotNull(s.approvals["ar_1"], "kept briefly: the PC normally sends approval_resolved{expired}")
        s = reducer.tick(s, atExpiry.plusSeconds(11)).state
        assertTrue(s.approvals.isEmpty())
        assertEquals(ApprovalOutcome.EXPIRED, s.history.find("ar_1")!!.outcome)
    }

    @Test
    fun `clock skew shifts expiry`() {
        // PC clock 30 s ahead: a request that expires at server T0+60 has only 30 s left on the phone.
        val req = T.request(id = "ar_1", created = now.minusSeconds(60), ttlSeconds = 120) // expires T0+60 server time
        var s = start()
        s = s.apply(T.welcome(serverTime = now.plusSeconds(30))).first
        assertEquals(30_000, s.clockSkewMs)
        s = s.apply(T.snapshot(10, approvals = listOf(req))).first
        assertEquals(1, s.pendingCards(now).size)
        assertTrue(s.pendingCards(now.plusSeconds(31)).isEmpty())
    }

    @Test
    fun `approval resolved moves the card into history without storing the command`() {
        val req = T.request(id = "ar_1", command = "SECRET-COMMAND --token abc")
        var s = synced(100).apply(T.approvalMsg(101, req)).first
        s = s.apply(T.resolvedMsg(102, "ar_1")).first
        assertTrue(s.approvals.isEmpty())
        val entry = s.history.find("ar_1")!!
        assertEquals(ApprovalOutcome.ALLOWED, entry.outcome)
        assertEquals("명령을 실행하려고 해요", entry.title)
        assertEquals(dev.agentnest.core.protocol.RiskLevel.HIGH, entry.riskLevel)
        assertFalse(entry.toString().contains("SECRET-COMMAND"))
    }

    @Test
    fun `observed result updates the same history entry in place`() {
        val req = T.request(id = "ar_1")
        var s = synced(100).apply(T.approvalMsg(101, req)).first
        s = s.apply(T.resolvedMsg(102, "ar_1")).first
        s = s.apply(T.resolvedMsg(103, "ar_1", observed = ObservedResult.EXECUTED)).first
        assertEquals(1, s.history.entries.size)
        assertEquals(ObservedResult.EXECUTED, s.history.entries.single().observedResult)
        assertEquals("명령을 실행하려고 해요", s.history.entries.single().title, "title survives the update")
    }

    @Test
    fun `history keeps at most 50 entries newest first`() {
        var s = synced(100)
        for (i in 1..60) {
            val id = "ar_$i"
            s = s.apply(T.approvalMsg(100L + 2 * i - 1, T.request(id = id))).first
            s = s.apply(T.resolvedMsg(100L + 2 * i, id)).first
        }
        assertEquals(50, s.history.entries.size)
        assertEquals("ar_60", s.history.entries.first().requestId)
        assertEquals("ar_11", s.history.entries.last().requestId)
    }

    @Test
    fun `a request resolved earlier is not resurrected by a late approval_request`() {
        var s = synced(100)
        s = s.apply(T.resolvedMsg(101, "ar_1")).first
        // A stale retransmission with a fresh seq (should not happen, but must not resurrect).
        val (next, out) = s.apply(T.approvalMsg(102, T.request(id = "ar_1")))
        assertTrue(next.approvals.isEmpty())
        assertTrue(out.isEmpty())
    }

    @Test
    fun `decision result applied keeps the card blocked until resolved`() {
        val req = T.request(id = "ar_1")
        var s = synced(100).apply(T.approvalMsg(101, req)).first
        s = reducer.markDecisionSent(s, "ar_1", "msg1", Decision.ALLOW, now)
        assertNotNull(s.approvals.getValue("ar_1").inFlight)
        s = s.apply(T.decisionResult("ar_1", true, DecisionResultReason.APPLIED)).first
        assertNotNull(s.approvals.getValue("ar_1").inFlight)
        s = s.apply(T.resolvedMsg(102, "ar_1")).first
        assertTrue(s.approvals.isEmpty())
    }

    @Test
    fun `decision result rejection clears in-flight so the user can retry`() {
        val req = T.request(id = "ar_1")
        var s = synced(100).apply(T.approvalMsg(101, req)).first
        s = reducer.markDecisionSent(s, "ar_1", "msg1", Decision.ALLOW, now)
        s = s.apply(T.decisionResult("ar_1", false, DecisionResultReason.AUTH_REQUIRED)).first
        val card = s.approvals.getValue("ar_1")
        assertNull(card.inFlight)
        assertEquals(DecisionResultReason.AUTH_REQUIRED, card.lastResult?.reason)
    }

    @Test
    fun `decision result expired or unknown closes the card`() {
        for (reason in listOf(DecisionResultReason.EXPIRED, DecisionResultReason.UNKNOWN_REQUEST)) {
            val req = T.request(id = "ar_1")
            var s = synced(100).apply(T.approvalMsg(101, req)).first
            s = s.apply(T.decisionResult("ar_1", false, reason)).first
            assertTrue(s.approvals.isEmpty(), "$reason")
            assertNotNull(s.history.find("ar_1"))
        }
    }

    @Test
    fun `losing the link forgets in-flight decisions so the user can decide again after reconnect`() {
        val req = T.request(id = "ar_1")
        var s = synced(100).apply(T.approvalMsg(101, req)).first
        s = reducer.markDecisionSent(s, "ar_1", "m1", Decision.ALLOW, now)
        s = reducer.onLink(s, LinkState.Offline, now.plusSeconds(1))
        assertNull(s.approvals.getValue("ar_1").inFlight)
    }

    @Test
    fun `placeholders whose body never arrives are dropped after the approval TTL`() {
        var s = synced(100)
        s = s.apply(T.snapshot(200, ids = listOf("ar_ghost"))).first
        assertTrue(s.approvals.getValue("ar_ghost").isLoading)
        s = reducer.tick(s, now.plusSeconds(100)).state
        assertTrue(s.approvals.containsKey("ar_ghost"))
        s = reducer.tick(s, now.plusSeconds(131)).state
        assertTrue(s.approvals.isEmpty())
    }

    // ---- events / sessions / adapters --------------------------------------------------------------

    @Test
    fun `timeline only event kinds never change session state or mood`() {
        var s = synced(100, listOf(T.session("claude_code:s1", AgentState.WORKING)))
        val before = s.sessions
        val moodBefore = s.mood.mood
        for ((i, kind) in listOf(EventKind.APPROVAL_REQUESTED, EventKind.APPROVAL_RESOLVED, EventKind.ADAPTER_STATUS).withIndex()) {
            s = s.apply(T.eventMsg(T.event(101L + i, kind, nativeIds = mapOf("request_id" to "ar_1")))).first
        }
        assertEquals(before, s.sessions)
        assertEquals(moodBefore, s.mood.mood)
        assertEquals(3, s.recentEvents.size, "different kinds keep separate timeline rows")
    }

    @Test
    fun `timeline only events are de-duplicated by kind and request id`() {
        var s = synced(100)
        s = s.apply(T.eventMsg(T.event(101, EventKind.APPROVAL_RESOLVED, nativeIds = mapOf("request_id" to "ar_1")))).first
        s = s.apply(T.eventMsg(T.event(102, EventKind.APPROVAL_RESOLVED, nativeIds = mapOf("request_id" to "ar_1")))).first
        assertEquals(1, s.recentEvents.size)
    }

    @Test
    fun `warning and error events feed recent errors capped at 5`() {
        var s = synced(100)
        for (i in 1..7) s = s.apply(T.eventMsg(T.event(100L + i, EventKind.COMMAND_FAILED, Severity.ERROR))).first
        assertEquals(5, s.recentErrors.size)
        assertEquals(107, s.recentErrors.last().seq)
        s = s.apply(T.eventMsg(T.event(108, EventKind.COMMAND_STARTED, Severity.INFO))).first
        assertEquals(5, s.recentErrors.size)
    }

    @Test
    fun `recent events are capped at 200`() {
        var s = synced(100)
        for (i in 1..250) s = s.apply(T.eventMsg(T.event(100L + i))).first
        assertEquals(NestReducer.MAX_RECENT_EVENTS, s.recentEvents.size)
        assertEquals(350, s.recentEvents.last().seq)
    }

    @Test
    fun `session state drives the mood`() {
        var s = synced(100)
        s = s.apply(T.sessionMsg(101, T.session("a", AgentState.AWAITING_APPROVAL, pending = listOf("ar_1")))).first
        assertEquals(KongiMood.RAISE_HAND, s.mood.mood)
        assertEquals("a", s.mood.primarySessionKey)
    }

    @Test
    fun `adapter status is stored`() {
        val s = synced(100).apply(T.adapterMsg(101, AdapterStatusKind.DEGRADED)).first
        assertEquals(AdapterStatusKind.DEGRADED, s.adapters.getValue(dev.agentnest.core.protocol.AgentKind.CODEX).status)
    }

    @Test
    fun `link changes update the mood and ended sessions are pruned`() {
        var s = synced(100, listOf(T.session("a", AgentState.WORKING, since = now.minusSeconds(900), ended = true, lastEvent = now.minusSeconds(900))))
        s = reducer.tick(s, now).state
        assertTrue(s.sessions.isEmpty(), "sessions that ended more than 10 minutes ago are dropped")
        s = reducer.onLink(s, LinkState.Offline, now.plusSeconds(1))
        assertEquals(KongiMood.SLEEPY, s.mood.mood)
    }

    // ---- cache / performance -----------------------------------------------------------------------

    @Test
    fun `restore from cache shows the last state with seq reset and a cache flag`() {
        val snap = T.snapshot(900, listOf(T.session("a", AgentState.TESTING)))
        val s = reducer.restoreFromCache(snap, savedAt = now.minusSeconds(180), now = now, link = LinkState.Offline)
        assertTrue(s.fromCache)
        assertEquals(0, s.lastSeq)
        assertEquals(now.minusSeconds(180), s.lastSyncAt)
        assertEquals(setOf("a"), s.sessions.keys)
        assertEquals(KongiMood.SLEEPY, s.mood.mood, "offline wins over the cached session mood")
    }

    @Test
    fun `one reduce step stays far below the 5 ms budget`() {
        val sessions = (1..20).map { T.session("s$it", AgentState.WORKING) }
        val approvals = (1..20).map { T.request(id = "ar_$it") }
        var s = synced(100)
        val snapshot = T.snapshot(200, sessions, approvals)
        // Warm up the JIT, then measure.
        repeat(200) { s = s.apply(snapshot).first }
        val start = System.nanoTime()
        val rounds = 500
        repeat(rounds) { s = s.apply(snapshot).first }
        val avgMs = (System.nanoTime() - start) / rounds / 1_000_000.0
        assertTrue(avgMs < 5.0, "average snapshot apply took $avgMs ms")
        var seq = 200L
        val sessionMsgs = 2000
        val t0 = System.nanoTime()
        repeat(sessionMsgs) { s = s.apply(T.sessionMsg(++seq, T.session("s1", AgentState.TESTING))).first }
        val avgUpdate = (System.nanoTime() - t0) / sessionMsgs / 1_000_000.0
        assertTrue(avgUpdate < 5.0, "average session_state apply took $avgUpdate ms")
    }
}
