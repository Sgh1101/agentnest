package dev.agentnest.core.link

import dev.agentnest.core.T
import dev.agentnest.core.protocol.AckMessage
import dev.agentnest.core.protocol.ByeMessage
import dev.agentnest.core.protocol.ByePayload
import dev.agentnest.core.protocol.ByeReason
import dev.agentnest.core.protocol.ChallengeMessage
import dev.agentnest.core.protocol.ChallengePayload
import dev.agentnest.core.protocol.ErrorMessage
import dev.agentnest.core.protocol.ErrorPayload
import dev.agentnest.core.protocol.HelloMessage
import dev.agentnest.core.protocol.HostsInfo
import dev.agentnest.core.protocol.HostsUpdateMessage
import dev.agentnest.core.protocol.HostsUpdatePayload
import dev.agentnest.core.protocol.PingMessage
import dev.agentnest.core.protocol.PongMessage
import dev.agentnest.core.protocol.PongPayload
import dev.agentnest.core.protocol.Ts
import dev.agentnest.core.protocol.UnpairMessage
import dev.agentnest.core.protocol.WelcomeMessage
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LinkStateMachineTest {
    private class Harness(hosts: HostBookState = HostBookState(port = 47832, qr = listOf("192.168.0.10", "10.8.0.2"))) {
        var now: Instant = T.T0
        var lastSeq = 0L
        var creds: DeviceCredentials? = DeviceCredentials("dev_1", "secret-token")
        val machine = LinkStateMachine(
            hosts = hosts,
            credentials = { creds },
            lastSeq = { lastSeq },
            backoff = BackoffPolicy(random = { 0.5 }), // exact base delays, no jitter
            ids = { T.id() },
        )
        var conn = 0L
        val log = ArrayList<LinkEffect>()

        val state get() = machine.state

        fun send(event: LinkEvent, advance: Duration = Duration.ZERO): List<LinkEffect> {
            now = now.plus(advance)
            val effects = machine.handle(event, now)
            effects.filterIsInstance<LinkEffect.OpenSocket>().lastOrNull()?.let { conn = it.connId }
            log += effects
            return effects
        }

        fun frame(message: dev.agentnest.core.protocol.ServerMessage, advance: Duration = Duration.ZERO) =
            send(LinkEvent.FrameReceived(conn, message), advance)

        fun fail(kind: TransportFailureKind = TransportFailureKind.UNREACHABLE, advance: Duration = Duration.ZERO) =
            send(LinkEvent.SocketFailed(conn, TransportFailure(kind, "x")), advance)

        fun closed(code: Int, advance: Duration = Duration.ZERO) = send(LinkEvent.SocketClosed(conn, code, "r"), advance)

        fun tick(advance: Duration = Duration.ZERO) = send(LinkEvent.Tick, advance)

        /** Start, receive the challenge and the welcome: ends in Connected. */
        fun connect() {
            send(LinkEvent.Start(paired = true))
            send(LinkEvent.SocketOpened(conn))
            frame(challenge())
            frame(T.welcome(at = now))
            assertIs<LinkState.Connected>(state)
        }

        fun challenge() = ChallengeMessage(T.meta(at = now), ChallengePayload("cXk4Z1l0d2VyN3U4aW9wMQ==", T.PC.pcId, Ts.of(now), 5000))
    }

    private fun secs(n: Long) = Duration.ofSeconds(n)

    // ---- handshake --------------------------------------------------------------------------------

    @Test
    fun `start connects to the first candidate host`() {
        val h = Harness()
        val effects = h.send(LinkEvent.Start(paired = true))
        assertEquals(LinkState.Connecting("192.168.0.10", 1), h.state)
        assertEquals(LinkEffect.OpenSocket(1, "192.168.0.10", 47832), effects.first())
    }

    @Test
    fun `start while unpaired stays unpaired and does nothing`() {
        val h = Harness()
        assertTrue(h.send(LinkEvent.Start(paired = false)).isEmpty())
        assertEquals(LinkState.Unpaired, h.state)
    }

    @Test
    fun `challenge is answered with hello echoing the challenge and lastSeq then welcome connects`() {
        val h = Harness()
        h.lastSeq = 1830
        h.send(LinkEvent.Start(paired = true))
        h.send(LinkEvent.SocketOpened(h.conn))
        val sent = h.frame(h.challenge()).filterIsInstance<LinkEffect.Send>().single().message
        val hello = assertIs<HelloMessage>(sent)
        assertEquals("dev_1", hello.payload.deviceId)
        assertEquals("cXk4Z1l0d2VyN3U4aW9wMQ==", hello.payload.challengeB64)
        assertEquals(1830, hello.payload.lastSeq)
        assertEquals(1, hello.payload.protocol)
        assertEquals(LinkState.Challenged, h.state)
        assertTrue(!hello.payload.toString().contains("secret-token"), "token must not leak through toString")

        val effects = h.frame(T.welcome(at = h.now))
        val connected = assertIs<LinkState.Connected>(h.state)
        assertEquals(T.PC, connected.pc)
        assertTrue(effects.any { it is LinkEffect.PersistHosts })
        assertEquals("192.168.0.10", h.machine.hosts.lastSuccess)
    }

    @Test
    fun `missing credentials at challenge time ends in Unpaired`() {
        val h = Harness()
        h.send(LinkEvent.Start(paired = true))
        h.creds = null
        h.send(LinkEvent.SocketOpened(h.conn))
        val effects = h.frame(h.challenge())
        assertEquals(LinkState.Unpaired, h.state)
        assertTrue(effects.any { it is LinkEffect.CloseSocket })
        assertTrue(effects.none { it is LinkEffect.Send })
    }

    @Test
    fun `welcome only counts after hello was sent`() {
        val h = Harness()
        h.send(LinkEvent.Start(paired = true))
        h.send(LinkEvent.SocketOpened(h.conn))
        h.frame(T.welcome(at = h.now))
        assertIs<LinkState.Connecting>(h.state, "welcome before challenge is ignored")
    }

    @Test
    fun `stale socket events are ignored`() {
        val h = Harness()
        h.send(LinkEvent.Start(paired = true))
        val old = h.conn
        h.fail() // first host failed, second host started (new connection id)
        val before = h.state
        h.send(LinkEvent.SocketFailed(old, TransportFailure(TransportFailureKind.UNREACHABLE, "late")))
        h.send(LinkEvent.SocketClosed(old, 4003, "late"))
        assertEquals(before, h.state)
    }

    // ---- hosts / backoff --------------------------------------------------------------------------

    @Test
    fun `host iteration tries every host before backing off`() {
        val h = Harness(HostBookState(welcome = listOf("192.168.0.20"), manual = listOf("192.168.0.30"), qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        assertEquals("192.168.0.20", (h.state as LinkState.Connecting).host)
        h.fail()
        assertEquals("192.168.0.30", (h.state as LinkState.Connecting).host)
        h.fail()
        assertEquals("192.168.0.10", (h.state as LinkState.Connecting).host)
        val effects = h.fail()
        val reconnecting = assertIs<LinkState.Reconnecting>(h.state)
        assertEquals(1, reconnecting.attempt)
        assertEquals(h.now.plusSeconds(1), reconnecting.nextAt)
        assertEquals(LinkError.Unreachable, reconnecting.lastError)
        assertTrue(effects.contains(LinkEffect.ScheduleWake(reconnecting.nextAt)))
    }

    @Test
    fun `backoff doubles and five failed rounds mean PcUnreachable`() {
        val h = Harness(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        val delays = ArrayList<Long>()
        repeat(4) {
            h.fail()
            val r = assertIs<LinkState.Reconnecting>(h.state)
            delays += Duration.between(h.now, r.nextAt).seconds
            h.tick(Duration.between(h.now, r.nextAt))
            assertIs<LinkState.Connecting>(h.state)
        }
        assertEquals(listOf(1L, 2L, 4L, 8L), delays)
        h.fail()
        assertIs<LinkState.PcUnreachable>(h.state)
        // Retries continue (capped by the schedule): next wake in 16 s, then 32 s, then 60 s.
        h.tick(secs(16))
        assertIs<LinkState.Connecting>(h.state)
        h.fail()
        assertIs<LinkState.PcUnreachable>(h.state)
    }

    @Test
    fun `ticks before the retry time do nothing`() {
        val h = Harness(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        h.fail()
        assertTrue(h.tick(Duration.ofMillis(500)).isEmpty())
        assertIs<LinkState.Reconnecting>(h.state)
        h.tick(Duration.ofMillis(500))
        assertIs<LinkState.Connecting>(h.state)
    }

    @Test
    fun `network available and connect now reset the backoff`() {
        val h = Harness(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        repeat(3) {
            h.fail()
            h.tick(secs(60))
        }
        h.fail()
        assertEquals(4, (h.state as LinkState.Reconnecting).attempt)
        h.send(LinkEvent.NetworkAvailable)
        assertEquals(LinkState.Connecting("192.168.0.10", 1), h.state)
        h.fail()
        assertEquals(1, (h.state as LinkState.Reconnecting).attempt)
        h.send(LinkEvent.ConnectNow)
        assertEquals(LinkState.Connecting("192.168.0.10", 1), h.state)
    }

    @Test
    fun `hosts changed while unreachable retries immediately`() {
        val h = Harness(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        repeat(5) {
            h.fail()
            if (h.state !is LinkState.PcUnreachable) h.tick(secs(60))
        }
        assertIs<LinkState.PcUnreachable>(h.state)
        h.send(LinkEvent.HostsChanged(HostBookState(manual = listOf("192.168.0.99"), qr = listOf("192.168.0.10"))))
        assertEquals(LinkState.Connecting("192.168.0.99", 1), h.state)
    }

    @Test
    fun `handshake timeout moves on to the next host`() {
        val h = Harness()
        h.send(LinkEvent.Start(paired = true))
        h.tick(secs(9))
        assertEquals("192.168.0.10", (h.state as LinkState.Connecting).host)
        val effects = h.tick(secs(1))
        assertEquals("10.8.0.2", (h.state as LinkState.Connecting).host)
        assertTrue(effects.contains(LinkEffect.AbortSocket))
    }

    @Test
    fun `hosts_update stores only private addresses and persists`() {
        val h = Harness()
        h.connect()
        val effects = h.frame(
            HostsUpdateMessage(T.meta(), HostsUpdatePayload(listOf("192.168.0.23", "8.8.8.8", "100.64.1.1", "evil.example.com"), 47900)),
        )
        val persisted = effects.filterIsInstance<LinkEffect.PersistHosts>().single().hosts
        assertEquals(listOf("192.168.0.23", "100.64.1.1"), persisted.welcome)
        assertEquals(47900, persisted.port)
        // The host that just worked stays first, then the addresses the PC announced, then the QR hosts.
        assertEquals(listOf("192.168.0.10", "192.168.0.23", "100.64.1.1", "10.8.0.2"), persisted.candidates())
    }

    // ---- terminal states --------------------------------------------------------------------------

    @Test
    fun `close 4003 means Revoked and nothing reconnects automatically`() {
        val h = Harness()
        h.connect()
        val effects = h.closed(4003)
        assertEquals(LinkState.Revoked("4003"), h.state)
        assertTrue(effects.contains(LinkEffect.WipeDeviceToken))
        assertTrue(effects.contains(LinkEffect.SecurityAlert(SecurityAlertKind.DEVICE_REVOKED)))
        for (event in listOf(LinkEvent.Tick, LinkEvent.NetworkAvailable, LinkEvent.ConnectNow, LinkEvent.NetworkLost)) {
            assertTrue(h.send(event, secs(3600)).isEmpty(), "$event must not do anything while revoked")
            assertEquals(LinkState.Revoked("4003"), h.state)
        }
    }

    @Test
    fun `E_DEVICE_REVOKED error and bye device_revoked both revoke`() {
        val a = Harness()
        a.send(LinkEvent.Start(paired = true))
        a.send(LinkEvent.SocketOpened(a.conn))
        a.frame(a.challenge())
        a.frame(ErrorMessage(T.meta(), ErrorPayload("E_DEVICE_REVOKED", "revoked", null, null, true)))
        assertEquals(LinkState.Revoked("E_DEVICE_REVOKED"), a.state)

        val b = Harness()
        b.connect()
        b.frame(ByeMessage(T.meta(), ByePayload(ByeReason.DEVICE_REVOKED, false, "해제")))
        assertEquals(LinkState.Revoked("device_revoked"), b.state)
    }

    @Test
    fun `three consecutive pin mismatches suspend for one hour`() {
        val h = Harness(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        h.fail(TransportFailureKind.PIN_MISMATCH)
        assertIs<LinkState.Reconnecting>(h.state)
        h.tick(secs(1))
        h.fail(TransportFailureKind.PIN_MISMATCH)
        h.tick(secs(2))
        val effects = h.fail(TransportFailureKind.PIN_MISMATCH)
        val suspended = assertIs<LinkState.Suspended>(h.state)
        assertEquals(h.now.plus(Duration.ofHours(1)), suspended.until)
        assertTrue(effects.contains(LinkEffect.SecurityAlert(SecurityAlertKind.PC_IDENTITY_CHANGED)))
        // No automatic attempt during the hour, even on network changes or explicit reconnect.
        assertTrue(h.tick(secs(1800)).isEmpty())
        assertTrue(h.send(LinkEvent.NetworkAvailable).isEmpty())
        assertTrue(h.send(LinkEvent.ConnectNow).isEmpty())
        assertIs<LinkState.Suspended>(h.state)
        // After an hour it tries again.
        h.tick(secs(1800))
        assertIs<LinkState.Connecting>(h.state)
    }

    @Test
    fun `a pin mismatch that persists after the suspension needs a repair`() {
        val h = Harness(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        repeat(3) { h.fail(TransportFailureKind.PIN_MISMATCH); if (h.state is LinkState.Reconnecting) h.tick(secs(60)) }
        assertIs<LinkState.Suspended>(h.state)
        h.tick(secs(3600))
        assertIs<LinkState.Connecting>(h.state)
        repeat(3) { h.fail(TransportFailureKind.PIN_MISMATCH); if (h.state is LinkState.Reconnecting) h.tick(secs(60)) }
        assertEquals(LinkState.NeedsRepair(RepairReason.IDENTITY_CHANGED), h.state)
        assertTrue(h.send(LinkEvent.Tick, secs(7200)).isEmpty())
        h.send(LinkEvent.UserRepair)
        assertEquals(LinkState.Unpaired, h.state)
    }

    @Test
    fun `a successful connection resets the pin mismatch counter`() {
        val h = Harness(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        h.fail(TransportFailureKind.PIN_MISMATCH)
        h.tick(secs(1))
        h.fail(TransportFailureKind.PIN_MISMATCH)
        h.tick(secs(2))
        h.send(LinkEvent.SocketOpened(h.conn))
        h.frame(h.challenge())
        h.frame(T.welcome(at = h.now))
        assertIs<LinkState.Connected>(h.state)
        h.fail(TransportFailureKind.PIN_MISMATCH) // connection later lost with a mismatch: counts as 1 again
        assertTrue(h.state !is LinkState.Suspended)
    }

    @Test
    fun `three E_AUTH_FAILED connections need a repair and error plus close count once`() {
        val h = Harness(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        repeat(2) { round ->
            h.send(LinkEvent.SocketOpened(h.conn))
            h.frame(h.challenge())
            h.frame(ErrorMessage(T.meta(), ErrorPayload("E_AUTH_FAILED", "auth", null, null, true)))
            h.closed(4002)
            assertIs<LinkState.Reconnecting>(h.state, "round $round")
            assertEquals(LinkError.AuthFailed, (h.state as LinkState.Reconnecting).lastError)
            h.tick(secs(60))
        }
        h.send(LinkEvent.SocketOpened(h.conn))
        h.frame(h.challenge())
        val effects = h.frame(ErrorMessage(T.meta(), ErrorPayload("E_AUTH_FAILED", "auth", null, null, true)))
        assertEquals(LinkState.NeedsRepair(RepairReason.AUTH_FAILED), h.state)
        assertTrue(effects.contains(LinkEffect.AbortSocket))
        assertTrue(h.send(LinkEvent.Tick, secs(3600)).isEmpty())
    }

    @Test
    fun `close 4002 without an error frame also counts`() {
        val h = Harness(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        repeat(2) {
            h.send(LinkEvent.SocketOpened(h.conn))
            h.frame(h.challenge())
            h.closed(4002)
            h.tick(secs(60))
        }
        h.send(LinkEvent.SocketOpened(h.conn))
        h.frame(h.challenge())
        h.closed(4002)
        assertEquals(LinkState.NeedsRepair(RepairReason.AUTH_FAILED), h.state)
    }

    @Test
    fun `a successful welcome resets the auth failure counter`() {
        val h = Harness(HostBookState(qr = listOf("192.168.0.10")))
        h.send(LinkEvent.Start(paired = true))
        repeat(2) {
            h.send(LinkEvent.SocketOpened(h.conn))
            h.frame(h.challenge())
            h.closed(4002)
            h.tick(secs(60))
        }
        h.send(LinkEvent.SocketOpened(h.conn))
        h.frame(h.challenge())
        h.frame(T.welcome(at = h.now))
        assertIs<LinkState.Connected>(h.state)
        h.closed(1006)
        h.tick(secs(60))
        h.send(LinkEvent.SocketOpened(h.conn))
        h.frame(h.challenge())
        h.closed(4002)
        assertIs<LinkState.Reconnecting>(h.state, "only one failure since the last success")
    }

    @Test
    fun `user repair clears revoked needs-repair and suspended and wipes the pairing`() {
        val revoked = Harness().also { it.connect(); it.closed(4003) }
        val repair = Harness(HostBookState(qr = listOf("192.168.0.10"))).also {
            it.send(LinkEvent.Start(paired = true))
            repeat(3) { _ ->
                it.send(LinkEvent.SocketOpened(it.conn)); it.frame(it.challenge()); it.closed(4002); it.tick(secs(60))
            }
        }
        val suspended = Harness(HostBookState(qr = listOf("192.168.0.10"))).also {
            it.send(LinkEvent.Start(paired = true))
            repeat(3) { _ -> it.fail(TransportFailureKind.PIN_MISMATCH); it.tick(secs(60)) }
        }
        for ((name, h) in listOf("revoked" to revoked, "repair" to repair, "suspended" to suspended)) {
            val effects = h.send(LinkEvent.UserRepair)
            assertEquals(LinkState.Unpaired, h.state, name)
            assertTrue(effects.contains(LinkEffect.WipePairing), name)
            assertEquals(HostBookState(), effects.filterIsInstance<LinkEffect.PersistHosts>().single().hosts, name)
        }
    }

    @Test
    fun `4009 means superseded and backs off`() {
        val h = Harness()
        h.connect()
        h.closed(4009)
        val r = assertIs<LinkState.Reconnecting>(h.state)
        assertEquals(LinkError.Superseded, r.lastError)
        assertEquals(1, r.attempt)
    }

    @Test
    fun `4010 and E_PROTO_VERSION mean incompatible`() {
        val a = Harness().also { it.connect(); it.closed(4010) }
        assertEquals(LinkState.Incompatible, a.state)
        val b = Harness()
        b.send(LinkEvent.Start(paired = true))
        b.send(LinkEvent.SocketOpened(b.conn))
        b.frame(ErrorMessage(T.meta(), ErrorPayload("E_PROTO_VERSION", "v", null, null, true)))
        assertEquals(LinkState.Incompatible, b.state)
        assertTrue(b.send(LinkEvent.Tick, secs(3600)).isEmpty())
    }

    @Test
    fun `bye shutdown without reconnect waits five minutes`() {
        val h = Harness()
        h.connect()
        val effects = h.frame(ByeMessage(T.meta(), ByePayload(ByeReason.SHUTDOWN, false, "PC에서 휴대폰 연결을 껐어요")))
        val r = assertIs<LinkState.Reconnecting>(h.state)
        assertEquals(h.now.plus(Duration.ofMinutes(5)), r.nextAt)
        assertEquals(LinkError.PcShutdown("PC에서 휴대폰 연결을 껐어요"), r.lastError)
        assertTrue(effects.any { it is LinkEffect.CloseSocket })
        h.closed(1000) // the close that follows is stale
        assertEquals(r, h.state)
        h.tick(secs(299))
        assertIs<LinkState.Reconnecting>(h.state)
        h.tick(secs(1))
        assertIs<LinkState.Connecting>(h.state)
    }

    @Test
    fun `bye restart and superseded reconnect with normal backoff`() {
        for (reason in listOf(ByeReason.RESTART, ByeReason.SUPERSEDED_CONNECTION)) {
            val h = Harness()
            h.connect()
            h.frame(ByeMessage(T.meta(), ByePayload(reason, true, null)))
            assertEquals(1, assertIs<LinkState.Reconnecting>(h.state).attempt, "$reason")
        }
    }

    @Test
    fun `incompatible and revoked ignore host changes`() {
        val h = Harness().also { it.connect(); it.closed(4010) }
        h.send(LinkEvent.HostsChanged(HostBookState(manual = listOf("192.168.0.5"))))
        assertEquals(LinkState.Incompatible, h.state)
    }

    // ---- connectivity / heartbeat -----------------------------------------------------------------

    @Test
    fun `network loss goes offline and aborts the socket, availability reconnects`() {
        val h = Harness()
        h.connect()
        val effects = h.send(LinkEvent.NetworkLost)
        assertEquals(LinkState.Offline, h.state)
        assertTrue(effects.contains(LinkEffect.AbortSocket))
        h.closed(1006) // stale
        assertEquals(LinkState.Offline, h.state)
        h.send(LinkEvent.NetworkAvailable)
        assertIs<LinkState.Connecting>(h.state)
    }

    @Test
    fun `no frame for 70 seconds drops the connection`() {
        val h = Harness()
        h.connect()
        // Keep the app-level heartbeat answered so only silence matters.
        h.tick(secs(69))
        assertIs<LinkState.Connected>(h.state)
        val effects = h.tick(secs(2))
        val r = assertIs<LinkState.Reconnecting>(h.state)
        assertEquals(LinkError.HeartbeatTimeout, r.lastError)
        assertTrue(effects.contains(LinkEffect.AbortSocket))
    }

    @Test
    fun `any received frame resets the silence timer`() {
        val h = Harness()
        h.connect()
        h.tick(secs(60))
        h.frame(PongMessage(T.meta(), PongPayload(null, Ts.of(h.now))))
        h.tick(secs(60))
        assertIs<LinkState.Connected>(h.state)
    }

    @Test
    fun `ping after 30 quiet seconds and rtt from the pong`() {
        val h = Harness()
        h.connect()
        assertTrue(h.tick(secs(29)).none { it is LinkEffect.Send })
        val effects = h.tick(secs(1))
        val ping = assertIs<PingMessage>(effects.filterIsInstance<LinkEffect.Send>().single().message)
        assertTrue(h.tick(secs(5)).none { it is LinkEffect.Send }, "no second ping right away")
        h.frame(PongMessage(T.meta(), PongPayload(ping.meta.id, Ts.of(h.now))), Duration.ofMillis(40))
        val connected = assertIs<LinkState.Connected>(h.state)
        assertEquals(40 + 5000, connected.rttMs)
    }

    @Test
    fun `acks are batched at most once per second and only when seq advanced`() {
        val h = Harness()
        h.connect()
        h.lastSeq = 10
        assertTrue(h.tick(Duration.ofMillis(500)).none { it is LinkEffect.Send }, "less than a second since the welcome")
        val first = h.tick(Duration.ofMillis(500)).filterIsInstance<LinkEffect.Send>().single().message
        assertEquals(10, assertIs<AckMessage>(first).payload.throughSeq)
        h.lastSeq = 11
        assertTrue(h.tick(Duration.ofMillis(300)).none { it is LinkEffect.Send })
        h.lastSeq = 15
        val second = h.tick(Duration.ofMillis(800)).filterIsInstance<LinkEffect.Send>().single().message
        assertEquals(15, assertIs<AckMessage>(second).payload.throughSeq)
        assertTrue(h.tick(secs(1)).none { it is LinkEffect.Send }, "nothing new to ack")
    }

    @Test
    fun `lost connection after being connected backs off from attempt one`() {
        val h = Harness()
        h.connect()
        h.fail(TransportFailureKind.UNREACHABLE)
        val r = assertIs<LinkState.Reconnecting>(h.state)
        assertEquals(1, r.attempt)
        assertEquals(LinkError.Unreachable, r.lastError)
    }

    @Test
    fun `unpair sends the message wipes everything and ends unpaired`() {
        val h = Harness()
        h.connect()
        val effects = h.send(LinkEvent.UserUnpair)
        assertEquals(LinkState.Unpaired, h.state)
        assertIs<UnpairMessage>(effects.filterIsInstance<LinkEffect.Send>().single().message)
        assertTrue(effects.contains(LinkEffect.WipePairing))
        assertNull(h.machine.hosts.lastSuccess)
    }
}
