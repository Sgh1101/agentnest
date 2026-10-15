package dev.agentnest.core.link

import dev.agentnest.core.T
import dev.agentnest.core.protocol.ChallengeMessage
import dev.agentnest.core.protocol.ChallengePayload
import dev.agentnest.core.protocol.Ts
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Review finding 15: pin-mismatch counting per round and persistence of the link counters across restarts. */
class LinkCountersTest {
    private class H(hosts: HostBookState, initial: LinkCounters = LinkCounters(), startAt: Instant = T.T0) {
        var now: Instant = startAt
        val machine = LinkStateMachine(
            hosts, { DeviceCredentials("dev_1", "secret") }, { 0L },
            backoff = BackoffPolicy(random = { 0.5 }), ids = { T.id() }, initialCounters = initial,
        )
        var conn = 0L
        val persisted = ArrayList<LinkCounters>()
        val state get() = machine.state

        fun send(event: LinkEvent, advance: Duration = Duration.ZERO): List<LinkEffect> {
            now = now.plus(advance)
            val effects = machine.handle(event, now)
            effects.filterIsInstance<LinkEffect.OpenSocket>().lastOrNull()?.let { conn = it.connId }
            effects.filterIsInstance<LinkEffect.PersistCounters>().forEach { persisted += it.counters }
            return effects
        }

        fun fail(kind: TransportFailureKind) = send(LinkEvent.SocketFailed(conn, TransportFailure(kind, "x")))
        fun tick(advance: Duration = Duration.ZERO) = send(LinkEvent.Tick, advance)
    }

    private fun secs(n: Long) = Duration.ofSeconds(n)

    @Test
    fun `a pin mismatch counts once per round not once per host`() {
        val h = H(HostBookState(qr = listOf("192.168.0.10", "192.168.0.11", "192.168.0.12")))
        h.send(LinkEvent.Start(true))
        // one round: three hosts, all mismatching -> ONE count, not three, so no suspension yet
        repeat(3) { h.fail(TransportFailureKind.PIN_MISMATCH) }
        assertIs<LinkState.Reconnecting>(h.state)
        assertEquals(1, h.persisted.last().pinMismatchRounds)
    }

    @Test
    fun `a stale address that mismatches next to unreachable hosts never suspends`() {
        val h = H(HostBookState(qr = listOf("192.168.0.99", "192.168.0.10")))
        h.send(LinkEvent.Start(true))
        repeat(10) {
            h.fail(TransportFailureKind.PIN_MISMATCH) // the stale IP now answers with another device's certificate
            h.fail(TransportFailureKind.UNREACHABLE) // the real PC is off
            assertTrue(h.state is LinkState.Reconnecting || h.state is LinkState.PcUnreachable, "round $it -> ${h.state}")
            h.tick(secs(3600))
        }
        assertTrue(h.persisted.none { it.pinMismatchRounds > 0 })
    }

    @Test
    fun `three all-mismatch rounds suspend and persist the suspension`() {
        val h = H(HostBookState(qr = listOf("192.168.0.10", "192.168.0.11")))
        h.send(LinkEvent.Start(true))
        repeat(3) {
            repeat(2) { h.fail(TransportFailureKind.PIN_MISMATCH) }
            if (h.state is LinkState.Reconnecting) h.tick(secs(60))
        }
        val suspended = assertIs<LinkState.Suspended>(h.state)
        val saved = h.persisted.last()
        assertEquals(suspended.until, saved.suspendedUntil)
        assertEquals(1, saved.suspensions)
    }

    @Test
    fun `a suspension survives a restart and the service does not connect during the hour`() {
        val until = T.T0.plus(Duration.ofHours(1))
        val restored = LinkCounters(pinMismatchRounds = 3, suspensions = 1, suspendedUntil = until)
        val h = H(HostBookState(qr = listOf("192.168.0.10")), restored, startAt = T.T0.plusSeconds(600))
        val effects = h.send(LinkEvent.Start(true))
        assertEquals(LinkState.Suspended(until), h.state)
        assertTrue(effects.none { it is LinkEffect.OpenSocket })
        assertTrue(h.send(LinkEvent.NetworkAvailable).isEmpty())
        // after the hour it tries again
        h.tick(Duration.ofHours(1))
        assertIs<LinkState.Connecting>(h.state)
        assertNull(h.persisted.last().suspendedUntil)
    }

    @Test
    fun `after a restart past the suspension a repeated mismatch escalates to identity changed`() {
        val restored = LinkCounters(pinMismatchRounds = 3, suspensions = 1, suspendedUntil = T.T0.plusSeconds(10))
        val h = H(HostBookState(qr = listOf("192.168.0.10")), restored, startAt = T.T0.plusSeconds(100))
        h.send(LinkEvent.Start(true))
        assertIs<LinkState.Connecting>(h.state)
        repeat(3) { h.fail(TransportFailureKind.PIN_MISMATCH); if (h.state is LinkState.Reconnecting) h.tick(secs(60)) }
        assertEquals(LinkState.NeedsRepair(RepairReason.IDENTITY_CHANGED), h.state)
        assertEquals(RepairReason.IDENTITY_CHANGED, h.persisted.last().needsRepair)
    }

    @Test
    fun `needs-repair survives a restart and nothing connects`() {
        val h = H(HostBookState(qr = listOf("192.168.0.10")), LinkCounters(authFailures = 3, needsRepair = RepairReason.AUTH_FAILED))
        val effects = h.send(LinkEvent.Start(true))
        assertEquals(LinkState.NeedsRepair(RepairReason.AUTH_FAILED), h.state)
        assertTrue(effects.none { it is LinkEffect.OpenSocket })
        // the user re-pairs: counters are wiped
        h.send(LinkEvent.UserRepair)
        assertEquals(LinkState.Unpaired, h.state)
        assertTrue(h.persisted.last().isClear)
    }

    @Test
    fun `auth failures are persisted and a welcome clears everything`() {
        val h = H(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(true))
        h.send(LinkEvent.SocketOpened(h.conn))
        h.send(LinkEvent.FrameReceived(h.conn, ChallengeMessage(T.meta(at = h.now), ChallengePayload("cXk4Z1l0d2VyN3U4aW9wMQ==", T.PC.pcId, Ts.of(h.now), 5000))))
        h.send(LinkEvent.SocketClosed(h.conn, 4002, "r"))
        assertEquals(1, h.persisted.last().authFailures)
        h.tick(secs(60))
        h.send(LinkEvent.SocketOpened(h.conn))
        h.send(LinkEvent.FrameReceived(h.conn, ChallengeMessage(T.meta(at = h.now), ChallengePayload("cXk4Z1l0d2VyN3U4aW9wMQ==", T.PC.pcId, Ts.of(h.now), 5000))))
        h.send(LinkEvent.FrameReceived(h.conn, T.welcome(at = h.now)))
        assertIs<LinkState.Connected>(h.state)
        assertTrue(h.persisted.last().isClear)
    }
}
