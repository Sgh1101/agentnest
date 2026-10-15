package dev.agentnest.core.tls

import dev.agentnest.core.crypto.SpkiPin
import dev.agentnest.core.link.OkHttpWsTransport
import dev.agentnest.core.link.TransportFailure
import dev.agentnest.core.link.TransportFailureKind
import dev.agentnest.core.link.WsCallbacks
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.ByteString.Companion.encodeUtf8
import java.net.InetAddress
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Real TLS handshakes against MockWebServer with self-signed certificates: the pinning cases of docs/android.md 3.3
 * exercised through [OkHttpWsTransport] (TrustManager + hostname verifier + CertificatePinner).
 */
class PinnedTransportTest {
    private sealed interface Outcome {
        data object Opened : Outcome
        data class Text(val text: String) : Outcome
        data class Closed(val code: Int) : Outcome
        data class Failed(val failure: TransportFailure) : Outcome
    }

    private val servers = mutableListOf<MockWebServer>()

    @AfterTest
    fun shutdown() {
        servers.forEach { runCatching { it.close() } }
    }

    private fun held(
        sans: List<String> = listOf("127.0.0.1"),
        notBefore: Instant? = null,
        notAfter: Instant? = null,
        keyPair: java.security.KeyPair? = null,
    ): HeldCertificate = HeldCertificate.Builder().apply {
        sans.forEach(::addSubjectAlternativeName)
        if (notBefore != null && notAfter != null) validityInterval(notBefore.toEpochMilli(), notAfter.toEpochMilli())
        if (keyPair != null) keyPair(keyPair)
    }.build()

    private fun startServer(certificate: HeldCertificate?, serverListener: WebSocketListener): MockWebServer {
        val server = MockWebServer()
        if (certificate != null) {
            server.useHttps(HandshakeCertificates.Builder().heldCertificate(certificate).build().sslSocketFactory())
        }
        server.enqueue(MockResponse.Builder().webSocketUpgrade(serverListener).build())
        server.start(InetAddress.getByName("127.0.0.1"), 0)
        servers += server
        return server
    }

    private val echo = object : WebSocketListener() {
        override fun onMessage(webSocket: WebSocket, text: String) {
            webSocket.send("echo:$text")
        }
    }

    private fun connect(server: MockWebServer, pin: SpkiPin, clock: Clock = Clock.systemUTC(), send: String? = null): LinkedBlockingQueue<Outcome> {
        val outcomes = LinkedBlockingQueue<Outcome>()
        val transport = OkHttpWsTransport(pin, clock)
        val connection = transport.open("127.0.0.1", server.port, object : WsCallbacks {
            override fun onOpen() {
                outcomes += Outcome.Opened
            }

            override fun onText(text: String) {
                outcomes += Outcome.Text(text)
            }

            override fun onClosed(code: Int, reason: String) {
                outcomes += Outcome.Closed(code)
            }

            override fun onFailure(failure: TransportFailure) {
                outcomes += Outcome.Failed(failure)
            }
        })
        if (send != null) {
            val opened = outcomes.poll(10, TimeUnit.SECONDS)
            assertEquals(Outcome.Opened, opened)
            assertTrue(connection.send(send))
        }
        return outcomes
    }

    private fun LinkedBlockingQueue<Outcome>.next(): Outcome = assertNotNull(poll(10, TimeUnit.SECONDS), "timed out waiting for an event")

    @Test
    fun `matching pin connects and exchanges text frames`() {
        val cert = held()
        val server = startServer(cert, echo)
        val outcomes = connect(server, SpkiPin.of(cert.certificate), send = "hello")
        assertEquals(Outcome.Text("echo:hello"), outcomes.next())
    }

    @Test
    fun `wrong pin fails as PIN_MISMATCH and nothing is sent`() {
        val received = LinkedBlockingQueue<String>()
        val listener = object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                received += text
            }
        }
        val server = startServer(held(), listener)
        val otherPin = SpkiPin.of(held().certificate)
        val outcome = connect(server, otherPin).next()
        val failed = assertIs<Outcome.Failed>(outcome)
        assertEquals(TransportFailureKind.PIN_MISMATCH, failed.failure.kind)
        assertTrue(received.isEmpty())
    }

    @Test
    fun `expired certificate fails even with the right pin`() {
        val now = Instant.now()
        val expired = held(notBefore = now.minusSeconds(7200), notAfter = now.minusSeconds(3600))
        val server = startServer(expired, echo)
        val failed = assertIs<Outcome.Failed>(connect(server, SpkiPin.of(expired.certificate)).next())
        assertTrue(failed.failure.kind == TransportFailureKind.TLS || failed.failure.kind == TransportFailureKind.UNREACHABLE, "${failed.failure}")
        assertTrue(failed.failure.kind != TransportFailureKind.PIN_MISMATCH, "an expired but correctly pinned cert is not an identity change")
    }

    @Test
    fun `the injected clock decides validity`() {
        val now = Instant.now()
        val future = held(notBefore = now.plusSeconds(3600), notAfter = now.plusSeconds(7200))
        val server = startServer(future, echo)
        // With the real clock the certificate is not yet valid ...
        assertIs<Outcome.Failed>(connect(server, SpkiPin.of(future.certificate)).next())
        // ... but valid for a clock that is an hour and a half ahead.
        val server2 = startServer(future, echo)
        val shifted = Clock.fixed(now.plusSeconds(5400), ZoneOffset.UTC)
        assertEquals(Outcome.Opened, connect(server2, SpkiPin.of(future.certificate), shifted).next())
    }

    @Test
    fun `reissued certificate with the same key and a new SAN still connects`() {
        val first = held(sans = listOf("192.168.0.10"))
        val reissued = held(sans = listOf("127.0.0.1", "10.9.9.9"), keyPair = first.keyPair)
        val server = startServer(reissued, echo)
        val outcomes = connect(server, SpkiPin.of(first.certificate), send = "again")
        assertEquals(Outcome.Text("echo:again"), outcomes.next())
    }

    @Test
    fun `plain text servers are never used (no ws fallback)`() {
        val server = startServer(null, echo)
        val cert = held()
        val outcomes = connect(server, SpkiPin.of(cert.certificate))
        // The TLS handshake can never complete against a plain-text server; end it by closing the server.
        Thread.sleep(500)
        server.close()
        assertIs<Outcome.Failed>(outcomes.next())
        // MockWebServer may have recorded the TLS bytes as garbage, but never a WebSocket upgrade over plain text.
        val recorded = server.takeRequest(100, TimeUnit.MILLISECONDS)
        assertEquals(null, recorded?.headers?.get("Upgrade"), "no cleartext WebSocket upgrade may reach the server")
    }

    @Test
    fun `binary frames from the server close the connection with 1003`() {
        val cert = held()
        val listener = object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                webSocket.send("ignored".encodeUtf8())
            }
        }
        val server = startServer(cert, listener)
        val outcomes = connect(server, SpkiPin.of(cert.certificate))
        assertEquals(Outcome.Opened, outcomes.next())
        val closed = assertIs<Outcome.Closed>(outcomes.next())
        assertEquals(1003, closed.code)
    }

    @Test
    fun `server initiated close is reported once with its code`() {
        val cert = held()
        val listener = object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                webSocket.close(4003, "revoked")
            }
        }
        val server = startServer(cert, listener)
        val outcomes = connect(server, SpkiPin.of(cert.certificate))
        assertEquals(Outcome.Opened, outcomes.next())
        assertEquals(Outcome.Closed(4003), outcomes.next())
        assertEquals(null, outcomes.poll(300, TimeUnit.MILLISECONDS), "no duplicate close / failure events")
    }

    @Test
    fun `unreachable port is classified as UNREACHABLE`() {
        val server = MockWebServer()
        server.start(InetAddress.getByName("127.0.0.1"), 0)
        val port = server.port
        server.close()
        val cert = held()
        val outcomes = LinkedBlockingQueue<Outcome>()
        OkHttpWsTransport(SpkiPin.of(cert.certificate)).open("127.0.0.1", port, object : WsCallbacks {
            override fun onOpen() = Unit
            override fun onText(text: String) = Unit
            override fun onClosed(code: Int, reason: String) = Unit
            override fun onFailure(failure: TransportFailure) {
                outcomes += Outcome.Failed(failure)
            }
        })
        val failed = assertIs<Outcome.Failed>(outcomes.next())
        assertEquals(TransportFailureKind.UNREACHABLE, failed.failure.kind)
    }
}
