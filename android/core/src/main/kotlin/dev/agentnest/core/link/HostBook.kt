package dev.agentnest.core.link

import dev.agentnest.core.protocol.QrPayload
import dev.agentnest.core.util.HostAddress

/**
 * Persistable PC address book. Attempt order is: the last host that worked, then addresses learned from
 * `welcome.hosts` / `hosts_update`, then manually entered addresses, then the QR `hosts[]`
 * (docs/android.md 3.2, protocol.md 4.5).
 */
data class HostBookState(
    val port: Int = DEFAULT_PORT,
    val welcome: List<String> = emptyList(),
    val manual: List<String> = emptyList(),
    val qr: List<String> = emptyList(),
    val lastSuccess: String? = null,
) {
    /** Hosts in attempt order, de-duplicated. */
    fun candidates(): List<String> {
        val ordered = LinkedHashSet<String>()
        val all = welcome + manual + qr
        lastSuccess?.takeIf { it in all }?.let(ordered::add)
        ordered.addAll(welcome)
        ordered.addAll(manual)
        ordered.addAll(qr)
        return ordered.toList()
    }

    /**
     * Replaces the PC-provided address list. Only private LAN IP literals are kept (at most [MAX_STORED]); the
     * rest is ignored even though the sender passed pin + hello authentication. [newPort] is adopted when valid.
     */
    fun withWelcomeHosts(addresses: List<String>, newPort: Int?): HostBookState {
        val filtered = addresses.filter { HostAddress.isPrivateLan(it) }.distinct().take(MAX_STORED)
        val adoptedPort = newPort?.takeIf { it in 1024..65535 } ?: port
        return copy(welcome = filtered, port = adoptedPort)
    }

    /** Adds a manually entered address (IP literal or host name). Invalid input leaves the book unchanged. */
    fun withManual(address: String): HostBookState {
        val trimmed = address.trim()
        if (!HostAddress.isValidHost(trimmed)) return this
        val updated = (listOf(trimmed) + manual.filter { it != trimmed }).take(MAX_STORED)
        return copy(manual = updated)
    }

    /** Remembers that [host] worked, so it is tried first next time. */
    fun withSuccess(host: String): HostBookState = copy(lastSuccess = host)

    companion object {
        const val DEFAULT_PORT: Int = 47832
        const val MAX_STORED: Int = 8

        /** Builds the initial book from a validated pairing QR. */
        fun fromQr(qr: QrPayload): HostBookState = HostBookState(port = qr.port, qr = qr.hosts.take(MAX_STORED))
    }
}
