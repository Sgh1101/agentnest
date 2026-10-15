package dev.agentnest.core.tls

import dev.agentnest.core.crypto.SpkiPin
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * Builds OkHttp clients that only talk TLS to the one pinned server key (security.md 3, docs/android.md 3.3):
 * [SpkiPinTrustManager] plus a hostname verifier that re-checks the pin (self-signed servers are reached by IP,
 * so hostnames carry no identity). Plain-text connection specs are excluded, so there is no `ws://` fallback.
 *
 * OkHttp's `CertificatePinner` is deliberately NOT used: for a self-signed leaf its certificate chain cleaner
 * cannot build a chain to a trusted root and rejects every handshake (verified against OkHttp 5.5.0 in
 * `PinnedTransportTest`). The two independent pin checks above are the defence in depth.
 */
object PinnedClientFactory {
    /** Interval of the WebSocket-level ping (protocol.md 8.1). */
    const val PING_INTERVAL_SECONDS: Long = 25

    /** Per-host TCP connect timeout (docs/android.md 3.2). */
    const val CONNECT_TIMEOUT_SECONDS: Long = 3

    /** Builds a client for [pin]; it can be shared by all hosts of the PC. */
    fun create(pin: SpkiPin, clock: Clock = Clock.systemUTC()): OkHttpClient {
        val trustManager = SpkiPinTrustManager(pin, clock)
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), null) }
        return OkHttpClient.Builder()
            // Android requires the 2-argument overload with the trust manager.
            .sslSocketFactory(context.socketFactory, trustManager)
            .hostnameVerifier { _, session ->
                try {
                    (session.peerCertificates.firstOrNull() as? X509Certificate)?.let(pin::matches) == true
                } catch (_: SSLPeerUnverifiedException) {
                    false
                }
            }
            .connectionSpecs(listOf(ConnectionSpec.RESTRICTED_TLS))
            .pingInterval(PING_INTERVAL_SECONDS, TimeUnit.SECONDS)
            .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .build()
    }
}
