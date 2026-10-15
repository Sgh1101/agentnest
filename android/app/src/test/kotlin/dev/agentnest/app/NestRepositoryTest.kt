package dev.agentnest.app

import dev.agentnest.app.data.NestRepository
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.ApprovalHistoryEntry
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.ApprovalOutcome
import dev.agentnest.core.protocol.Delivery
import dev.agentnest.core.protocol.ObservedResult
import dev.agentnest.core.protocol.ResolvedBy
import dev.agentnest.core.protocol.RiskLevel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import java.time.Clock
import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class NestRepositoryTest {
    private val clock: Clock = Clock.fixed(TD.T0, ZoneOffset.UTC)

    @Test
    fun coldStartShowsTheCachedSnapshotAsConnecting() = runTest {
        val repo = NestRepository(backgroundScope, clock)
        val snapshot = TD.snapshot(7, sessions = listOf(TD.session("claude_code:s1", AgentState.WORKING)))
        repo.restore(snapshot, TD.T0.minusSeconds(180), paired = true)
        val state = repo.nest.value
        assertTrue(state.link is LinkState.Connecting)
        assertTrue(state.fromCache)
        assertEquals(1, state.sessions.size)
        assertEquals(TD.T0.minusSeconds(180), state.lastSyncAt)
        // Cached state never carries approval cards: they expire within minutes and hold command text.
        assertTrue(state.approvals.isEmpty())
    }

    @Test
    fun unpairedColdStartIgnoresAnyCache() = runTest {
        val repo = NestRepository(backgroundScope, clock)
        repo.restore(TD.snapshot(7, sessions = listOf(TD.session("a", AgentState.WORKING))), TD.T0, paired = false)
        assertEquals(LinkState.Unpaired, repo.nest.value.link)
        assertTrue(repo.nest.value.sessions.isEmpty())
    }

    @Test
    fun revokedPairingShowsTheRepairState() = runTest {
        val repo = NestRepository(backgroundScope, clock)
        repo.restore(null, null, paired = true)
        repo.markRevoked()
        assertTrue(repo.nest.value.link is LinkState.Revoked)
        assertFalse(repo.paused.value)
    }

    @Test
    fun historySurvivesAColdStart() = runTest {
        val repo = NestRepository(backgroundScope, clock)
        val entry = ApprovalHistoryEntry(
            requestId = "ar_1", sessionKey = "k", title = "t", toolName = "Bash", agentLabel = "Claude Code", projectName = "p",
            riskLevel = RiskLevel.HIGH, outcome = ApprovalOutcome.ALLOWED, resolvedBy = ResolvedBy.PHONE, resolvedAt = TD.T0,
            delivery = Delivery.DELIVERED, observedResult = ObservedResult.EXECUTED, messageKo = null,
        )
        repo.restore(null, null, paired = true, history = listOf(entry))
        assertEquals(listOf(entry), repo.nest.value.history.entries)
        repo.restore(null, null, paired = false, history = listOf(entry))
        assertTrue(repo.nest.value.history.entries.isEmpty())
    }

    @Test
    fun commandsAreNoOpsWithoutAServiceAndDecisionsAreNeverQueued() = runTest {
        val repo = NestRepository(backgroundScope, clock)
        repo.refresh()
        repo.connectNow()
        assertFalse(repo.connectedToService)
        val built = dev.agentnest.core.protocol.DecisionMessage(
            TD.meta(),
            dev.agentnest.core.protocol.DecisionPayload(
                "ar_x", "k", "n", "h", dev.agentnest.core.protocol.Decision.DENY, null, dev.agentnest.core.protocol.Ts.of(TD.T0), null, null,
            ),
        )
        assertFalse(repo.submitDecision(built))
        assertFalse(repo.send(built))
    }
}
