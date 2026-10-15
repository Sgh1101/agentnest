package dev.agentnest.core.link

import dev.agentnest.core.T
import dev.agentnest.core.protocol.EventsPageMessage
import dev.agentnest.core.protocol.EventsPagePayload
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.util.HostAddress
import dev.agentnest.core.util.Uuid7Generator
import java.util.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BackoffPolicyTest {
    @Test
    fun `base schedule is 1 2 4 8 16 32 60 60`() {
        val p = BackoffPolicy(random = { 0.5 })
        assertEquals(listOf(1L, 2L, 4L, 8L, 16L, 32L, 60L, 60L, 60L), (1..9).map { p.baseSeconds(it) })
        assertEquals(1L, p.baseSeconds(0))
        assertEquals(60L, p.baseSeconds(1000))
    }

    @Test
    fun `jitter stays within plus or minus 20 percent`() {
        val low = BackoffPolicy(random = { 0.0 })
        val high = BackoffPolicy(random = { 0.999999 })
        for (attempt in 1..8) {
            val base = low.baseSeconds(attempt) * 1000.0
            assertEquals((base * 0.8).toLong(), low.delay(attempt).toMillis())
            assertTrue(high.delay(attempt).toMillis() <= (base * 1.2).toLong() + 1)
            assertTrue(high.delay(attempt).toMillis() >= base)
        }
        val p = BackoffPolicy()
        repeat(200) {
            val d = p.delay(7).toMillis()
            assertTrue(d in 48_000..72_000, "$d")
        }
    }
}

class SeqTrackerTest {
    @Test
    fun `classification`() {
        assertEquals(SeqVerdict.APPLY, SeqTracker.classify(10, 11, false))
        assertEquals(SeqVerdict.DUPLICATE, SeqTracker.classify(10, 10, false))
        assertEquals(SeqVerdict.DUPLICATE, SeqTracker.classify(10, 3, false))
        assertEquals(SeqVerdict.GAP, SeqTracker.classify(10, 12, false))
        assertEquals(SeqVerdict.AWAITING_SNAPSHOT, SeqTracker.classify(10, 11, true))
        assertEquals(SeqVerdict.AWAITING_SNAPSHOT, SeqTracker.classify(10, 500, true))
    }
}

class ClockSkewTest {
    @Test
    fun `skew conversion round trips`() {
        val phone = T.T0
        val server = phone.plusSeconds(7)
        val skew = ClockSkew.measure(server, phone)
        assertEquals(7000, skew)
        assertEquals(server, ClockSkew.toServer(phone, skew))
        assertEquals(phone, ClockSkew.toPhone(server, skew))
    }
}

class HostBookTest {
    private val port = HostBookState.DEFAULT_PORT

    @Test
    fun `attempt order is welcome then manual then QR`() {
        val book = HostBookState(welcome = listOf("192.168.0.20"), manual = listOf("192.168.0.30"), qr = listOf("192.168.0.10", "10.8.0.2"))
        assertEquals(listOf("192.168.0.20", "192.168.0.30", "192.168.0.10", "10.8.0.2"), book.candidates())
    }

    @Test
    fun `the last successful host goes first and duplicates collapse`() {
        val book = HostBookState(welcome = listOf("192.168.0.20", "192.168.0.10"), qr = listOf("192.168.0.10")).withSuccess("192.168.0.10")
        assertEquals(listOf("192.168.0.10", "192.168.0.20"), book.candidates())
        assertEquals(listOf("192.168.0.20"), book.copy(lastSuccess = "1.2.3.4").candidates().filter { it != "192.168.0.10" })
    }

    @Test
    fun `welcome hosts keep only private LAN literals, at most eight`() {
        val many = (1..12).map { "192.168.1.$it" }
        val book = HostBookState().withWelcomeHosts(listOf("8.8.8.8", "evil.example.com", "172.32.0.1") + many, null)
        assertEquals(8, book.welcome.size)
        assertTrue(book.welcome.all { it.startsWith("192.168.1.") })
        assertEquals(port, book.port)
    }

    @Test
    fun `welcome hosts replace the previous list and adopt a valid port`() {
        var book = HostBookState(welcome = listOf("192.168.0.1")).withWelcomeHosts(listOf("10.0.0.2"), 48000)
        assertEquals(listOf("10.0.0.2"), book.welcome)
        assertEquals(48000, book.port)
        book = book.withWelcomeHosts(listOf("10.0.0.3"), 80)
        assertEquals(48000, book.port, "ports below 1024 are ignored")
    }

    @Test
    fun `manual hosts are validated deduplicated and newest first`() {
        var book = HostBookState()
        book = book.withManual(" 192.168.0.50 ").withManual("192.168.0.51").withManual("192.168.0.50")
        assertEquals(listOf("192.168.0.50", "192.168.0.51"), book.manual)
        assertEquals(book, book.withManual("not a host!"))
        assertEquals(book, book.withManual(""))
        assertEquals(listOf("pc.lan"), HostBookState().withManual("pc.lan").manual)
    }

    @Test
    fun `private range checks`() {
        for (ok in listOf("10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1", "100.64.0.1", "100.127.255.255", "fc00::1", "fd12:3456::1")) {
            assertTrue(HostAddress.isPrivateLan(ok), ok)
        }
        for (bad in listOf("8.8.8.8", "172.15.0.1", "172.32.0.1", "100.63.0.1", "100.128.0.1", "192.169.0.1", "fe80::1", "::1", "2001:db8::1", "example.com", "", "010.0.0.1")) {
            assertFalse(HostAddress.isPrivateLan(bad), bad)
        }
    }

    @Test
    fun `host syntax`() {
        for (ok in listOf("192.168.0.10", "pc-1.local", "DESKTOP", "::1", "fe80::1", "::ffff:192.168.0.1")) assertTrue(HostAddress.isValidHost(ok), ok)
        for (bad in listOf("", "http://x", "a b", "1.2.3", "999.1.1.1", "-bad.com", "a..b", "[::1]", "1:2:3:4:5:6:7:8:9", "a/b")) assertFalse(HostAddress.isValidHost(bad), bad)
        assertNotNull(HostAddress.parseIpv6("2001:db8::8:800:200c:417a"))
        assertNull(HostAddress.parseIpv6("2001:db8::8::1"))
    }
}

class EventsPagerTest {
    private val now = T.T0

    private fun page(inReplyTo: String, seqs: List<Long>, hasMore: Boolean, next: Long?, omitted: Boolean = false) =
        EventsPageMessage(T.meta(), EventsPagePayload(inReplyTo, seqs.map { T.event(it) }, hasMore, next, omitted))

    @Test
    fun `first request uses the given bound and later ones use next_before_seq (exclusive)`() {
        var pager = EventsPager(sessionKey = "claude_code:s1")
        val first = pager.next(firstPageBeforeSeq = 1843, limit = 50, requestId = "r1", now = now)
        pager = first.pager
        val firstMessage = first.message!!
        assertEquals(1843, firstMessage.payload.beforeSeq)
        assertEquals("claude_code:s1", firstMessage.payload.sessionKey)
        assertEquals(50, firstMessage.payload.limit)
        assertTrue(pager.loading)
        assertNull(pager.next(1843, 50, "r-dup", now).message, "no second request while one is pending")

        pager = pager.onPage(page("r1", listOf(1800, 1810, 1820), hasMore = true, next = 1800))
        assertEquals(listOf(1800L, 1810L, 1820L), pager.events.map { it.seq })
        val second = pager.next(1843, 50, "r2", now)
        assertEquals(1800, second.message!!.payload.beforeSeq)
        pager = second.pager.onPage(page("r2", listOf(1700, 1750, 1810), hasMore = false, next = null, omitted = true))
        assertEquals(listOf(1700L, 1750L, 1800L, 1810L, 1820L), pager.events.map { it.seq }, "merged by seq, no duplicates")
        assertFalse(pager.hasMore)
        assertTrue(pager.detailOmitted)
        assertNull(pager.next(1843, 50, "r3", now).message, "nothing left to load")
    }

    @Test
    fun `limit is clamped to 1 through 100 and kinds to 16 known values`() {
        val kinds = EventKind.entries.filter { it != EventKind.UNKNOWN }.take(20) + EventKind.UNKNOWN
        val req = EventsPager(kinds = kinds).next(10, 500, "r", now).message!!.payload
        assertEquals(100, req.limit)
        val requested = req.kinds!!
        assertEquals(16, requested.size)
        assertTrue(requested.none { it == EventKind.UNKNOWN })
        assertEquals(1, EventsPager().next(10, 0, "r", now).message!!.payload.limit)
    }

    @Test
    fun `pages answering another request are ignored and pending can be cancelled`() {
        val started = EventsPager().next(10, 50, "r1", now).pager
        val ignored = started.onPage(page("other", listOf(1), hasMore = true, next = 1))
        assertEquals(started, ignored)
        val cancelled = started.cancelPending()
        assertFalse(cancelled.loading)
        assertNotNull(cancelled.next(10, 50, "r2", now).message)
        assertNotSame(started, cancelled)
    }
}

class Uuid7Test {
    @Test
    fun `generates lowercase UUIDv7 with the right version and variant`() {
        val gen = Uuid7Generator({ 1_760_000_000_123L }, Random(1))
        val pattern = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        val ids = (1..200).map { gen.next() }
        assertTrue(ids.all { pattern.matches(it) }, ids.first())
        assertEquals(200, ids.toSet().size)
        // 48-bit big-endian millisecond timestamp prefix
        val hex = ids.first().replace("-", "").substring(0, 12)
        assertEquals(1_760_000_000_123L, hex.toLong(16))
    }
}

