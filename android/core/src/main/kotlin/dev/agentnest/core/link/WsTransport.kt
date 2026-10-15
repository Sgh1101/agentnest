package dev.agentnest.core.link

import dev.agentnest.core.crypto.SpkiPin
import dev.agentnest.core.tls.PinFailure
import dev.agentnest.core.tls.PinnedCertificateException
import dev.agentnest.core.tls.PinnedClientFactory
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import java.io.IOException
import java.security.cert.CertificateException
import java.time.Clock
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException

/** How a transport attempt failed. Drives backoff and the pin-mismatch suspension. */
enum class TransportFailureKind {
    /** The server key does not match the pinned key (possible MITM or a different PC at that address). */
    PIN_MISMATCH,

    /** TCP connect/read failure or timeout. */
    UNREACHABLE,

    /** TLS failed for another reason (expired certificate, handshake failure, ...). */
    TLS,

    /** HTTP upgrade refused or protocol violation (binary frame, wrong subprotocol, ...). */
    PROTOCOL,
}

/** A transport-level failure. [message] never contains secrets. */
data class TransportFailure(val kind: TransportFailureKind, val message: String)

/** Events delivered by a [WsConnection]. Called from the transport's own threads. */
interface WsCallbacks {
    /** The WebSocket upgrade completed. */
    fun onOpen()

    /** One text frame arrived. */
    fun onText(text: String)

    /** The peer (or [WsConnection.close]) closed the connection with [code]. Delivered at most once. */
    fun onClosed(code: Int, reason: String)

    /** The connection failed. Delivered at most once and never after [onClosed]. */
    fun onFailure(failure: TransportFailure)
}

/** An open (or opening) WebSocket. */
interface WsConnection {
    /** Queues a text frame; false when the connection is closed or the send queue is full. */
    fun send(text: String): Boolean

    /** Starts a graceful close. */
    fun close(code: Int, reason: String)

    /** Aborts immediately without a close handshake. */
    fun cancel()
}

/** Opens `wss://host:port/v1/link` connections. */
fun interface WsTransport {
    /** Starts connecting; results are reported through [callbacks]. */
    fun open(host: String, port: Int, callbacks: WsCallbacks): WsConnection
}

/**
 * OkHttp-backed [WsTransport] that only trusts [pin] (see [PinnedClientFactory]). Sends the
 * `Sec-WebSocket-Protocol: agentnest.v1` subprotocol header.
 */
class OkHttpWsTransport(
    private val pin: SpkiPin,
    clock: Clock = Clock.systemUTC(),
    private val baseClient: OkHttpClient = PinnedClientFactory.create(pin, clock),
) : WsTransport {

    override fun open(host: String, port: Int, callbacks: WsCallbacks): WsConnection {
        val authority = if (host.contains(':')) "[$host]" else host
        val request = Request.Builder()
            .url("wss://$authority:$port/v1/link")
            .header("Sec-WebSocket-Protocol", SUBPROTOCOL)
            .build()
        val finished = AtomicBoolean(false)
        val socket = baseClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) = callbacks.onOpen()

            override fun onMessage(webSocket: WebSocket, text: String) = callbacks.onText(text)

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                // Binary frames are a protocol violation (protocol.md 1): close and report right away.
                webSocket.close(CLOSE_UNSUPPORTED_DATA, "binary frames are not supported")
                if (finished.compareAndSet(false, true)) callbacks.onClosed(CLOSE_UNSUPPORTED_DATA, "binary frames are not supported")
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                if (finished.compareAndSet(false, true)) callbacks.onClosed(code, reason)
                webSocket.close(code.takeIf { it in 1000..4999 && it != 1005 && it != 1006 } ?: 1000, "")
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (finished.compareAndSet(false, true)) callbacks.onClosed(code, reason)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (finished.compareAndSet(false, true)) callbacks.onFailure(classify(t, response))
            }
        })
        return object : WsConnection {
            override fun send(text: String): Boolean = socket.send(text)
            override fun close(code: Int, reason: String) {
                socket.close(code, reason)
            }

            override fun cancel() = socket.cancel()
        }
    }

    /** Releases the client's threads and pooled connections (tests, process shutdown). Open sockets are cancelled. */
    fun shutdown() {
        baseClient.dispatcher.cancelAll()
        baseClient.dispatcher.executorService.shutdown()
        baseClient.connectionPool.evictAll()
    }

    companion object {
        const val SUBPROTOCOL = "agentnest.v1"
        private const val CLOSE_UNSUPPORTED_DATA = 1003

        /** Maps an OkHttp failure to a [TransportFailure] without leaking certificate or token data. */
        fun classify(t: Throwable, response: Response?): TransportFailure {
            if (response != null) {
                return TransportFailure(TransportFailureKind.PROTOCOL, "upgrade refused (HTTP ${response.code})")
            }
            var cause: Throwable? = t
            var depth = 0
            while (cause != null && depth < 8) {
                if (cause is PinnedCertificateException) {
                    return if (cause.failure == PinFailure.PIN_MISMATCH) {
                        TransportFailure(TransportFailureKind.PIN_MISMATCH, "server key does not match the pin")
                    } else {
                        TransportFailure(TransportFailureKind.TLS, "server certificate rejected: ${cause.failure}")
                    }
                }
                // Raised by the hostname verifier / CertificatePinner second layer.
                if (cause is SSLPeerUnverifiedException) {
                    return TransportFailure(TransportFailureKind.PIN_MISMATCH, "server key does not match the pin")
                }
                cause = cause.cause
                depth++
            }
            return when (t) {
                is SSLException, is CertificateException -> TransportFailure(TransportFailureKind.TLS, "TLS failure")
                is IOException -> TransportFailure(TransportFailureKind.UNREACHABLE, t.javaClass.simpleName)
                else -> TransportFailure(TransportFailureKind.UNREACHABLE, t.javaClass.simpleName)
            }
        }
    }
}
