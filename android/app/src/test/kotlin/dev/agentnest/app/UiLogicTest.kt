package dev.agentnest.app

import dev.agentnest.app.data.HostBookCodec
import dev.agentnest.app.data.PairedInfo
import dev.agentnest.app.ui.Format
import dev.agentnest.app.ui.Tone
import dev.agentnest.app.ui.activity.EventFilter
import dev.agentnest.app.ui.agents.AgentGroups
import dev.agentnest.app.ui.common.LinkBannerLogic
import dev.agentnest.app.ui.projects.ProjectList
import dev.agentnest.app.ui.settings.Diagnostics
import dev.agentnest.app.ui.settings.formatSas
import dev.agentnest.core.link.LinkError
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.link.RepairReason
import dev.agentnest.core.nest.NestReducer
import dev.agentnest.core.protocol.AgentKind
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.Severity
import dev.agentnest.core.protocol.Ts
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UiLogicTest {
    @Test
    fun eventFiltersSelectTheRightKinds() {
        val failed = TD.event(1, EventKind.TOOL_FAILED)
        val warned = TD.event(2, EventKind.NOTIFICATION, Severity.WARNING)
        val done = TD.event(3, EventKind.TURN_COMPLETED)
        val approval = TD.event(4, EventKind.APPROVAL_RESOLVED)
        val file = TD.event(5, EventKind.FILE_MODIFIED)
        val command = TD.event(6, EventKind.COMMAND_COMPLETED)
        assertTrue(EventFilter.ERRORS.matches(failed) && EventFilter.ERRORS.matches(warned))
        assertFalse(EventFilter.ERRORS.matches(done))
        assertTrue(EventFilter.DONE.matches(done))
        assertTrue(EventFilter.APPROVALS.matches(approval))
        assertTrue(EventFilter.FILES.matches(file))
        assertTrue(EventFilter.COMMANDS.matches(command))
        assertTrue(EventFilter.ALL.matches(file))
        assertFalse(EventFilter.COMMANDS.matches(file))
    }

    @Test
    fun agentGroupsPutClaudeBeforeCodex() {
        val sessions = listOf(
            TD.session("codex:1", AgentState.REVIEWING, AgentKind.CODEX),
            TD.session("claude_code:1", AgentState.WORKING),
            TD.session("claude_code:2", AgentState.IDLE),
        )
        val groups = AgentGroups.of(sessions)
        assertEquals(listOf(AgentKind.CLAUDE_CODE, AgentKind.CODEX), groups.map { it.kind })
        assertEquals(2, groups[0].sessions.size)
    }

    @Test
    fun projectsAreDerivedFromSessions() {
        val sessions = listOf(
            TD.session("claude_code:1", AgentState.WORKING, projectKey = "p1", projectName = "agentnest"),
            TD.session("codex:1", AgentState.REVIEWING, AgentKind.CODEX, projectKey = "p1", projectName = "agentnest"),
            TD.session("claude_code:2", AgentState.IDLE, projectKey = "p2", projectName = "other", lastEvent = TD.T0.minusSeconds(500)),
        )
        val projects = ProjectList.of(sessions)
        assertEquals(listOf("agentnest", "other"), projects.map { it.name })
        assertEquals(listOf("Claude", "Codex"), projects[0].agents)
        assertEquals("main", projects[0].branch)
    }

    @Test
    fun linkBannerChoosesTheRightRecoveryActions() {
        val now = TD.T0
        assertNull(LinkBannerLogic.model(TD.connected(), false, now))
        assertNull(LinkBannerLogic.model(LinkState.Unpaired, false, now))
        assertEquals(Tone.MUTED, LinkBannerLogic.model(TD.connected(), true, now)!!.tone)
        val reconnecting = LinkBannerLogic.model(LinkState.Reconnecting(3, now.plusSeconds(8), LinkError.Unreachable), false, now)!!
        assertTrue(reconnecting.canReconnect)
        assertTrue(reconnecting.text.contains("3번째"))
        val unreachable = LinkBannerLogic.model(LinkState.PcUnreachable(now), false, now)!!
        assertTrue(unreachable.unreachable && unreachable.canReconnect)
        for (state in listOf(LinkState.NeedsRepair(RepairReason.AUTH_FAILED), LinkState.Revoked("E_DEVICE_REVOKED"), LinkState.Suspended(now.plusSeconds(3600)))) {
            val model = LinkBannerLogic.model(state, false, now)!!
            assertTrue(model.needsRepair)
            assertEquals(Tone.DANGER, model.tone)
            assertFalse("no automatic retry button for $state", model.canReconnect)
        }
        assertFalse(LinkBannerLogic.model(LinkState.Offline, false, now)!!.canReconnect)
        assertFalse(LinkBannerLogic.model(LinkState.Incompatible, false, now)!!.needsRepair)
    }

    @Test
    fun diagnosticsReportStateButNeverSecrets() {
        val reducer = NestReducer()
        var state = reducer.initial(TD.T0, TD.connected())
        state = reducer.reduce(state, TD.welcome(), TD.T0).state
        state = reducer.reduce(state, TD.snapshot(5, approvals = listOf(TD.request(command = "SECRETCOMMAND"))), TD.T0).state
        val paired = PairedInfo("dev_1", TD.PC.pcId, "DESKTOP-HOME", listOf("192.168.0.10"), true)
        val lines = Diagnostics.lines(state, paired, TD.T0)
        val text = lines.joinToString("\n") { "${it.label}=${it.value}" }
        assertTrue(text.contains("Connected"))
        assertTrue(text.contains("events_history"))
        assertFalse(text.contains("SECRETCOMMAND"))
        assertFalse(text.contains("sha256/"))
        assertNotNull(lines.firstOrNull { it.value == "1" })
    }

    @Test
    fun hostBookCodecRoundTrips() {
        val hosts = listOf("192.168.0.10", "fe80::1", "pc.local")
        assertEquals(hosts, HostBookCodec.decode(HostBookCodec.encode(hosts)))
        assertEquals(emptyList<String>(), HostBookCodec.decode(null))
        assertEquals(emptyList<String>(), HostBookCodec.decode(""))
        assertEquals(listOf("a", "b"), HostBookCodec.decode(" a , ,b "))
    }

    @Test
    fun sasIsGroupedInThrees() {
        assertEquals("482 915", formatSas("482915"))
    }

    @Test
    fun formatHelpers() {
        assertEquals("abc…", Format.shorten("abcdef", 4))
        assertEquals("abc", Format.shorten("abc", 4))
        val ts = Ts.of(TD.T0)
        assertEquals("방금 전", Format.ago(ts, TD.T0, 0))
        assertEquals("1분 전", Format.ago(ts, TD.T0.plusSeconds(61), 0))
        assertNull(Format.ago(null, TD.T0, 0))
        // A PC clock that is 60 s ahead: the same server timestamp is 60 s "older" on the phone timeline.
        assertEquals("1분 전", Format.ago(ts, TD.T0, 60_000))
    }
}

class ApprovalHistoryCodecTest {
    private fun entry(id: String, outcome: dev.agentnest.core.protocol.ApprovalOutcome) = dev.agentnest.core.nest.ApprovalHistoryEntry(
        requestId = id, sessionKey = "claude_code:s1", title = "명령을 실행하려고 해요", toolName = "Bash",
        agentLabel = "Claude Code", projectName = "agentnest", riskLevel = dev.agentnest.core.protocol.RiskLevel.HIGH,
        outcome = outcome, resolvedBy = dev.agentnest.core.protocol.ResolvedBy.PHONE, resolvedAt = TD.T0,
        delivery = dev.agentnest.core.protocol.Delivery.DELIVERED,
        observedResult = dev.agentnest.core.protocol.ObservedResult.EXECUTED, messageKo = "허용했어요",
    )

    @Test
    fun roundTripsEntries() {
        val history = dev.agentnest.core.nest.ApprovalHistory(
            listOf(entry("ar_1", dev.agentnest.core.protocol.ApprovalOutcome.ALLOWED), entry("ar_2", dev.agentnest.core.protocol.ApprovalOutcome.DENIED)),
        )
        val decoded = dev.agentnest.app.data.ApprovalHistoryCodec.decode(dev.agentnest.app.data.ApprovalHistoryCodec.encode(history))
        assertEquals(history.entries, decoded)
    }

    @Test
    fun storedTextHasNoCommandField() {
        val text = dev.agentnest.app.data.ApprovalHistoryCodec.encode(
            dev.agentnest.core.nest.ApprovalHistory(listOf(entry("ar_1", dev.agentnest.core.protocol.ApprovalOutcome.ALLOWED))),
        )
        assertFalse(text.contains("command"))
        assertFalse(text.contains("nonce"))
    }

    @Test
    fun damagedOrUnknownInputIsHandledSafely() {
        assertEquals(emptyList<dev.agentnest.core.nest.ApprovalHistoryEntry>(), dev.agentnest.app.data.ApprovalHistoryCodec.decode("{not json"))
        assertEquals(emptyList<dev.agentnest.core.nest.ApprovalHistoryEntry>(), dev.agentnest.app.data.ApprovalHistoryCodec.decode(null))
        val decoded = dev.agentnest.app.data.ApprovalHistoryCodec.decode(
            """[{"request_id":"ar_x","outcome":"from_the_future","resolved_by":"alien","delivery":"???"},{"no_id":true}]""",
        )
        assertEquals(1, decoded.size)
        assertEquals(dev.agentnest.core.protocol.ApprovalOutcome.UNKNOWN, decoded[0].outcome)
        assertEquals(dev.agentnest.core.protocol.ResolvedBy.UNKNOWN, decoded[0].resolvedBy)
    }

    @Test
    fun noMoreThanFiftyEntriesAreRestored() {
        val many = (1..80).map { """{"request_id":"ar_$it","outcome":"allowed"}""" }.joinToString(",", "[", "]")
        assertEquals(50, dev.agentnest.app.data.ApprovalHistoryCodec.decode(many).size)
    }
}
