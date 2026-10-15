package dev.agentnest.core.tls

import dev.agentnest.core.crypto.SpkiPin
import okhttp3.tls.HeldCertificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The four pinning cases listed in docs/android.md 3.3 / security.md I2, plus edge cases. */
class SpkiPinTrustManagerTest {
    private fun cert(
        sans: List<String> = listOf("127.0.0.1"),
        notBefore: Instant? = null,
        notAfter: Instant? = null,
        keyPair: java.security.KeyPair? = null,
    ): HeldCertificate = HeldCertificate.Builder().apply {
        sans.forEach(::addSubjectAlternativeName)
        if (notBefore != null && notAfter != null) validityInterval(notBefore.toEpochMilli(), notAfter.toEpochMilli())
        if (keyPair != null) keyPair(keyPair)
    }.build()

    private fun trustManager(pin: HeldCertificate, clock: Clock = Clock.systemUTC()) =
        SpkiPinTrustManager(SpkiPin.of(pin.certificate), clock)

    private fun chain(vararg certs: HeldCertificate): Array<X509Certificate> = certs.map { it.certificate }.toTypedArray()

    @Test
    fun `case 1 matching pin is accepted`() {
        val server = cert()
        trustManager(server).checkServerTrusted(chain(server), "ECDHE_ECDSA")
    }

    @Test
    fun `case 2 wrong pin is rejected as a pin mismatch`() {
        val server = cert()
        val other = cert()
        val e = assertFailsWith<PinnedCertificateException> { trustManager(other).checkServerTrusted(chain(server), "ECDHE_ECDSA") }
        assertEquals(PinFailure.PIN_MISMATCH, e.failure)
    }

    @Test
    fun `case 3 expired certificate is rejected even though the pin matches`() {
        val now = Instant.parse("2026-10-15T12:00:00Z")
        val expired = cert(notBefore = now.minusSeconds(7200), notAfter = now.minusSeconds(3600))
        val clock = Clock.fixed(now, ZoneOffset.UTC)
        val e = assertFailsWith<PinnedCertificateException> { trustManager(expired, clock).checkServerTrusted(chain(expired), "ECDHE_ECDSA") }
        assertEquals(PinFailure.EXPIRED_OR_NOT_YET_VALID, e.failure)
    }

    @Test
    fun `case 4 no certificates is rejected`() {
        val server = cert()
        val tm = trustManager(server)
        assertEquals(PinFailure.NO_CERTIFICATE, assertFailsWith<PinnedCertificateException> { tm.checkServerTrusted(emptyArray(), "x") }.failure)
        assertEquals(PinFailure.NO_CERTIFICATE, assertFailsWith<PinnedCertificateException> { tm.checkServerTrusted(null, "x") }.failure)
    }

    @Test
    fun `not yet valid certificate is rejected`() {
        val now = Instant.parse("2026-10-15T12:00:00Z")
        val future = cert(notBefore = now.plusSeconds(3600), notAfter = now.plusSeconds(7200))
        val e = assertFailsWith<PinnedCertificateException> {
            trustManager(future, Clock.fixed(now, ZoneOffset.UTC)).checkServerTrusted(chain(future), "x")
        }
        assertEquals(PinFailure.EXPIRED_OR_NOT_YET_VALID, e.failure)
    }

    @Test
    fun `a reissued certificate with the same key and different SAN is accepted`() {
        val first = cert(sans = listOf("192.168.0.10"))
        val reissued = cert(sans = listOf("192.168.0.77", "10.0.0.5"), keyPair = first.keyPair)
        trustManager(first).checkServerTrusted(chain(reissued), "ECDHE_ECDSA")
    }

    @Test
    fun `only the leaf is considered, extra certificates cannot smuggle trust`() {
        val server = cert()
        val attacker = cert()
        // Attacker leaf followed by the pinned certificate as a "CA": must fail.
        assertFailsWith<PinnedCertificateException> { trustManager(server).checkServerTrusted(chain(attacker, server), "x") }
        // Pinned leaf followed by junk: fine.
        trustManager(server).checkServerTrusted(chain(server, attacker), "x")
    }

    @Test
    fun `client authentication is never supported and no issuers are advertised`() {
        val server = cert()
        val tm = trustManager(server)
        assertFailsWith<CertificateException> { tm.checkClientTrusted(chain(server), "x") }
        assertTrue(tm.acceptedIssuers.isEmpty())
    }
}
