package dev.agentnest.core.util

/**
 * Pure (no DNS) host syntax checks and LAN-range classification. Used for QR hosts, `welcome.hosts`,
 * `hosts_update` and manual "IP direct input" (docs/android.md 3.2, protocol.md 4.5).
 */
object HostAddress {
    private val HOSTNAME_LABEL = Regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

    /** Parses a dotted-quad IPv4 literal (no leading zeros) into 4 octets, or null. */
    fun parseIpv4(text: String): IntArray? {
        val parts = text.split('.')
        if (parts.size != 4) return null
        val out = IntArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
            if (p.length > 1 && p[0] == '0') return null
            val v = p.toInt()
            if (v > 255) return null
            out[i] = v
        }
        return out
    }

    /** Parses an IPv6 literal (no brackets, no zone id) into 8 16-bit groups, or null. */
    fun parseIpv6(text: String): IntArray? {
        if (!text.contains(':') || text.length > 45) return null
        if (!text.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) return null
        val doubleColon = text.indexOf("::")
        if (doubleColon != text.lastIndexOf("::")) return null
        fun groups(part: String): List<Int>? {
            if (part.isEmpty()) return emptyList()
            val pieces = part.split(':')
            val out = ArrayList<Int>()
            for ((idx, piece) in pieces.withIndex()) {
                if (piece.contains('.')) {
                    if (idx != pieces.lastIndex) return null
                    val v4 = parseIpv4(piece) ?: return null
                    out += (v4[0] shl 8) or v4[1]
                    out += (v4[2] shl 8) or v4[3]
                } else {
                    if (piece.isEmpty() || piece.length > 4) return null
                    out += piece.toInt(16)
                }
            }
            return out
        }
        val result = IntArray(8)
        if (doubleColon >= 0) {
            val head = groups(text.substring(0, doubleColon)) ?: return null
            val tail = groups(text.substring(doubleColon + 2)) ?: return null
            if (head.size + tail.size > 7) return null
            head.forEachIndexed { i, g -> result[i] = g }
            tail.forEachIndexed { i, g -> result[8 - tail.size + i] = g }
        } else {
            val all = groups(text) ?: return null
            if (all.size != 8) return null
            all.forEachIndexed { i, g -> result[i] = g }
        }
        return result
    }

    /** True for an IPv4 or IPv6 literal. */
    fun isIpLiteral(text: String): Boolean = parseIpv4(text) != null || parseIpv6(text) != null

    /** True when [text] is an IP literal or a syntactically valid DNS host name. */
    fun isValidHost(text: String): Boolean {
        if (text.isEmpty() || text.length > 253) return false
        if (isIpLiteral(text)) return true
        if (text.contains(':')) return false
        val labels = text.split('.')
        return labels.all { HOSTNAME_LABEL.matches(it) } && !text.all { it in '0'..'9' || it == '.' }
    }

    /**
     * True for addresses in the private LAN ranges the phone is willing to store from the PC:
     * 10/8, 172.16/12, 192.168/16, 100.64/10 and fc00::/7.
     */
    fun isPrivateLan(text: String): Boolean {
        parseIpv4(text)?.let { o ->
            return o[0] == 10 ||
                (o[0] == 172 && o[1] in 16..31) ||
                (o[0] == 192 && o[1] == 168) ||
                (o[0] == 100 && o[1] in 64..127)
        }
        parseIpv6(text)?.let { g -> return (g[0] ushr 8) and 0xFE == 0xFC }
        return false
    }
}
