package dev.agentnest.core.tls

import dev.agentnest.core.crypto.SpkiPin
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.Date
import javax.net.ssl.X509TrustManager

/** Why [SpkiPinTrustManager] refused a server certificate. */
enum class PinFailure { NO_CERTIFICATE, PIN_MISMATCH, EXPIRED_OR_NOT_YET_VALID }

/** Thrown by [SpkiPinTrustManager]; [failure] lets callers distinguish a changed PC identity from other TLS errors. */
class PinnedCertificateException(val failure: PinFailure, message: String) : CertificateException(message)

/**
 * Trusts exactly one server key (security.md 3): the leaf certificate's SPKI SHA-256 must equal [pin]
 * (constant-time comparison) and the leaf must be currently valid. There is no CA chain, no hostname
 * check (the hostname verifier re-checks the pin instead) and no client authentication.
 *
 * Intermediate certificates sent by the server are ignored; only the leaf is considered. Reissuing a
 * certificate with the same key (new SAN / validity) therefore keeps working.
 */
class SpkiPinTrustManager(
    private val pin: SpkiPin,
    private val clock: Clock = Clock.systemUTC(),
) : X509TrustManager {

    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
        val leaf = chain?.firstOrNull() ?: throw PinnedCertificateException(PinFailure.NO_CERTIFICATE, "server sent no certificate")
        if (!pin.matches(leaf)) throw PinnedCertificateException(PinFailure.PIN_MISMATCH, "SPKI pin mismatch")
        try {
            leaf.checkValidity(Date.from(clock.instant()))
        } catch (e: CertificateException) {
            throw PinnedCertificateException(PinFailure.EXPIRED_OR_NOT_YET_VALID, "certificate is not currently valid")
        }
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {
        throw CertificateException("client authentication is not supported")
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}
