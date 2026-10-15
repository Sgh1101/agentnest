package dev.agentnest.core.text

import dev.agentnest.core.T
import dev.agentnest.core.link.LinkError
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.link.RepairReason
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TextTest {
    private val now = T.T0

    @Test
    fun `relative time`() {
        assertEquals("방금 전", RelativeTime.ago(now.minusSeconds(3), now))
        assertEquals("방금 전", RelativeTime.ago(now.plusSeconds(30), now))
        assertEquals("30초 전", RelativeTime.ago(now.minusSeconds(30), now))
        assertEquals("3분 전", RelativeTime.ago(now.minusSeconds(185), now))
        assertEquals("59분 전", RelativeTime.ago(now.minusSeconds(3599), now))
        assertEquals("2시간 전", RelativeTime.ago(now.minusSeconds(7300), now))
        assertEquals("2일 전", RelativeTime.ago(now.minusSeconds(2 * 86_400L + 5), now))
    }

    @Test
    fun `countdown`() {
        assertEquals("1:48", RelativeTime.countdown(108))
        assertEquals("0:05", RelativeTime.countdown(5))
        assertEquals("0:00", RelativeTime.countdown(-3))
    }

    @Test
    fun `link headlines cover every state`() {
        val pc = T.PC
        val all = listOf(
            LinkState.Unpaired, LinkState.Connecting("h", 1), LinkState.Challenged,
            LinkState.Reconnecting(3, now.plusSeconds(8), LinkError.Unreachable), LinkState.Offline,
            LinkState.PcUnreachable(now), LinkState.NeedsRepair(RepairReason.AUTH_FAILED),
            LinkState.NeedsRepair(RepairReason.IDENTITY_CHANGED), LinkState.Revoked("4003"),
            LinkState.Suspended(now.plusSeconds(3600)), LinkState.Incompatible,
        )
        for (s in all) assertTrue(Fallbacks.linkHeadline(s, now).isNotBlank(), "$s")
        assertEquals("", Fallbacks.linkHeadline(LinkState.Connected(pc, now, null), now))
        assertEquals("PC와 연결이 끊겼어요 · 다시 연결 중 (3번째, 8초 후)", Fallbacks.linkHeadline(all[3], now))
        assertEquals("다른 곳에서 연결됐어요 · 다시 연결 중 (1번째, 0초 후)", Fallbacks.linkHeadline(LinkState.Reconnecting(1, now, LinkError.Superseded), now))
    }
}
