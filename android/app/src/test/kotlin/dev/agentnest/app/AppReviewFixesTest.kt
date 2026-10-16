package dev.agentnest.app

import dev.agentnest.app.approval.ApprovalStatus
import dev.agentnest.app.approval.AuthText
import dev.agentnest.app.data.SnapshotRedaction
import dev.agentnest.app.notify.NotificationTexts
import dev.agentnest.app.ui.Labels
import dev.agentnest.app.ui.agents.AgentGroups
import dev.agentnest.app.ui.approvals.CommandFold
import dev.agentnest.app.ui.projects.ProjectList
import dev.agentnest.app.vault.VaultAction
import dev.agentnest.app.vault.VaultResult
import dev.agentnest.app.vault.VaultRetry
import dev.agentnest.core.nest.ApprovalCard
import dev.agentnest.core.nest.ApprovalHistoryEntry
import dev.agentnest.core.nest.InFlightDecision
import dev.agentnest.core.protocol.AgentKind
import dev.agentnest.core.protocol.AgentState
import dev.agentnest.core.protocol.ApprovalOutcome
import dev.agentnest.core.protocol.Decision
import dev.agentnest.core.protocol.DecisionResultPayload
import dev.agentnest.core.protocol.DecisionResultReason
import dev.agentnest.core.protocol.Delivery
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.ExtraConfirmationLevel
import dev.agentnest.core.protocol.ObservedResult
import dev.agentnest.core.protocol.Project
import dev.agentnest.core.protocol.RecentCommand
import dev.agentnest.core.protocol.RecentFile
import dev.agentnest.core.protocol.ResolvedBy
import dev.agentnest.core.protocol.RiskLevel
import dev.agentnest.core.protocol.Summary
import dev.agentnest.core.protocol.TurnInfo
import dev.agentnest.core.protocol.Ts
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Tests for the Android review fixes: server text sanitising, prompt text, snapshot cache, vault retries, folding. */
class AppReviewFixesTest {
    private val rlo = "‮"
    private val zwsp = "​"

    // ---- server text goes through the display sanitiser ----------------------------------------------------------
    @Test
    fun agentAndPcLabelsAreSanitised() {
        assertEquals("Claude⟨U+202E⟩ Code", Labels.agent(AgentKind.CLAUDE_CODE, "Claude$rlo Code"))
        assertEquals(AgentKind.CODEX.shortName, Labels.agent(AgentKind.CODEX, ""))
        assertEquals("PC⟨U+200B⟩1", Labels.pcName("PC${zwsp}1"))
        assertEquals("", Labels.pcName(null))
        assertEquals("DESKTOP-HOME", Labels.pcName("DESKTOP-HOME"))
    }

    @Test
    fun linkStatusNotificationShowsAnEscapedPcName() {
        val text = NotificationTexts.linkStatus(TD.connected(), "HOME$rlo", false, TD.T0)
        assertEquals("연결됨 · HOME⟨U+202E⟩", text)
        assertFalse(text.contains(rlo))
    }

    @Test
    fun approvalNotificationEscapesAgentLabelAndTitle() {
        val request = TD.request().copy(agentLabel = "Claude$zwsp", title = "실행$rlo")
        val text = NotificationTexts.approval(request, 60)
        assertFalse(text.title.contains(zwsp))
        assertFalse(text.body.contains(rlo))
        assertTrue(text.title.contains("⟨U+200B⟩"))
    }

    @Test
    fun projectListEscapesNamePathBranchAndAgents() {
        val session = TD.session("claude_code:s1", AgentState.WORKING).copy(
            agentLabel = "Claude$rlo",
            project = Project("p", "agent${zwsp}nest", pathHint = "C:\\w$rlo", branch = "main$rlo"),
        )
        val project = ProjectList.of(listOf(session)).single()
        assertEquals("agent⟨U+200B⟩nest", project.name)
        assertEquals("C:\\w⟨U+202E⟩", project.pathHint)
        assertEquals("main⟨U+202E⟩", project.branch)
        assertEquals(listOf("Claude⟨U+202E⟩"), project.agents)
        // grouping and groups are not affected by display escaping
        assertEquals(1, AgentGroups.of(listOf(session)).size)
    }

    private fun entry(title: String = "t", agent: String = "Claude Code", message: String? = null) = ApprovalHistoryEntry(
        requestId = TD.REQUEST_ID, sessionKey = "k", title = title, toolName = "Bash", agentLabel = agent,
        projectName = "p", riskLevel = RiskLevel.HIGH, outcome = ApprovalOutcome.ALLOWED, resolvedBy = ResolvedBy.PHONE,
        resolvedAt = TD.T0, delivery = Delivery.DELIVERED, observedResult = ObservedResult.EXECUTED, messageKo = message,
    )

    @Test
    fun historyLinesEscapeAgentLabelAndMessage() {
        val lines = ApprovalStatus.resolved(entry(agent = "Claude$rlo Code", message = "처리${zwsp}됨"))
        assertTrue(lines.joinToString("\n"), lines.none { it.contains(rlo) || it.contains(zwsp) })
        assertTrue(lines.any { it.contains("⟨U+200B⟩") })
        // an ordinary entry is unchanged
        assertEquals("허용했어요 · Claude에 전달했어요", ApprovalStatus.resolved(entry())[0])
    }

    @Test
    fun rejectedDecisionMessageIsEscaped() {
        val rejected = DecisionResultPayload(TD.REQUEST_ID, "m1", false, DecisionResultReason.AUTH_REQUIRED, "인증$rlo")
        val card = ApprovalCard(TD.REQUEST_ID, TD.request(), TD.T0, null, rejected)
        assertEquals("인증⟨U+202E⟩", ApprovalStatus.progress(card, TD.T0))
        // a message made only of a hidden character is still shown (escaped), a blank one falls back to the default text
        val blank = rejected.copy(messageKo = " ")
        assertEquals("PC가 이 결정을 받아들이지 않았어요", ApprovalStatus.progress(card.copy(lastResult = blank), TD.T0))
        assertNotEquals(null, ApprovalStatus.progress(card.copy(inFlight = InFlightDecision("m", Decision.ALLOW, TD.T0), lastResult = null), TD.T0))
    }

    // ---- biometric prompt text -----------------------------------------------------------------------------------
    @Test
    fun multiLineCommandGetsAMoreLinesSuffix() {
        assertEquals("ls -la (+1줄)", AuthText.description(TD.request(command = "ls -la\nsecond line")))
        // blank lines are not counted
        assertEquals("a (+2줄)", AuthText.description(TD.request(command = "a\n\n  b  \n\nc\n")))
        assertEquals("ls -la", AuthText.description(TD.request(command = "ls -la\n\n")))
        assertEquals("ls -la", AuthText.description(TD.request(command = "ls -la")))
    }

    @Test
    fun multiLineSuffixKeepsTheTotalWithinEightyCharacters() {
        val long = "echo " + "a".repeat(200) + "\nrm -rf /\nmore"
        val first = AuthText.description(TD.request(command = long)).lineSequence().first()
        assertTrue(first.length <= 80)
        assertTrue(first.endsWith("… (+2줄)"))
    }

    @Test
    fun hiddenNoteStaysOnTheSecondLineWithTheSuffix() {
        val text = AuthText.description(TD.request(command = "echo x$rlo\nnext"))
        val lines = text.lines()
        assertEquals("echo x⟨U+202E⟩ (+1줄)", lines[0])
        assertTrue(lines[1].contains("보이지 않는 문자 1개"))
    }

    // ---- cold-start cache ----------------------------------------------------------------------------------------
    @Test
    fun snapshotCacheKeepsNoCommandPathPromptOrDetailText() {
        val event = TD.event(3, EventKind.COMMAND_COMPLETED).copy(
            summary = Summary("명령을 마쳤어요", detail = "SECRET-DETAIL"),
            detail = JsonObject(mapOf("command" to JsonPrimitive("SECRET-COMMAND"))),
            project = Project("p", "agentnest", pathHint = "C:\\secret\\path"),
        )
        val session = TD.session("claude_code:s1", AgentState.WORKING, pending = listOf(TD.REQUEST_ID)).copy(
            project = Project("p", "agentnest", pathHint = "C:\\secret\\path", branch = "main"),
            detail = "SECRET-SESSION-DETAIL",
            turn = TurnInfo(active = true, promptPreview = "SECRET-PROMPT"),
            recentFiles = listOf(RecentFile("C:\\secret\\file.txt", "update", Ts.of(TD.T0))),
            recentCommands = listOf(RecentCommand("SECRET-CMD", "other", 0, Ts.of(TD.T0))),
        )
        val message = TD.snapshot(5, sessions = listOf(session), approvals = listOf(TD.request(command = "SECRET-APPROVAL")), events = listOf(event))
        val stripped = SnapshotRedaction.strip(message)
        val text = dev.agentnest.core.protocol.Codec.encodeAny(stripped)
        for (secret in listOf("SECRET-", "secret")) assertFalse("$secret leaked: $text", text.contains(secret))
        // what a cold start needs is still there
        val kept = stripped.payload.sessions.single()
        assertEquals("agentnest", kept.project.name)
        assertEquals("main", kept.project.branch)
        assertEquals(AgentState.WORKING, kept.state)
        assertEquals(session.headline, kept.headline)
        assertTrue(kept.turn.active)
        assertNull(kept.turn.promptPreview)
        assertTrue(kept.recentFiles.isEmpty() && kept.recentCommands.isEmpty())
        assertEquals("명령을 마쳤어요", stripped.payload.recentEvents.single().summary.headline)
        assertTrue(stripped.payload.pendingApprovals.isEmpty() && stripped.payload.pendingApprovalIdsComplete.isEmpty())
        assertEquals(message.meta, stripped.meta)
    }

    // ---- token vault ---------------------------------------------------------------------------------------------
    @Test
    fun aMissingKeyIsRecheckedBeforeThePairingIsTreatedAsLost() {
        for (attempt in 0 until VaultRetry.KEY_MISSING_RETRIES) {
            assertEquals(VaultAction.RETRY, VaultRetry.action(VaultResult.KeyMissing, attempt))
        }
        assertEquals(VaultAction.WIPE_PAIRING, VaultRetry.action(VaultResult.KeyMissing, VaultRetry.KEY_MISSING_RETRIES))
        // every delay used for those retries exists, and transient failures still never wipe
        assertTrue(VaultRetry.KEY_MISSING_RETRIES <= VaultRetry.DELAYS_MS.size)
        for (attempt in 0..20) assertNotEquals(VaultAction.WIPE_PAIRING, VaultRetry.action(VaultResult.Transient, attempt))
    }

    // ---- folded command ------------------------------------------------------------------------------------------
    @Test
    fun aShortCommandCutByTheLayoutStillGetsTheToggle() {
        val short = "echo hello"
        assertFalse(CommandFold.showToggle(short, clippedByLayout = false, expanded = false))
        assertTrue(CommandFold.showToggle(short, clippedByLayout = true, expanded = false))
        assertTrue("an expanded block can always be folded again", CommandFold.showToggle(short, clippedByLayout = false, expanded = true))
        assertTrue(CommandFold.showToggle("x".repeat(121), clippedByLayout = false, expanded = false))
        assertTrue(CommandFold.showToggle("a\nb\nc\nd\ne", clippedByLayout = false, expanded = false))
    }

    @Test
    fun aCutOffCommandMustBeExpandedBeforeARiskyAllow() {
        val hold = ExtraConfirmationLevel.HOLD
        assertTrue(CommandFold.mustExpandBeforeAllow(true, clippedByLayout = true, expanded = false, extraConfirmation = hold))
        assertTrue(CommandFold.mustExpandBeforeAllow(true, true, false, ExtraConfirmationLevel.HOLD_AND_RECONFIRM))
        // unknown extra confirmation counts as the strongest one
        assertTrue(CommandFold.mustExpandBeforeAllow(true, true, false, ExtraConfirmationLevel.UNKNOWN))
        assertFalse("expanded", CommandFold.mustExpandBeforeAllow(true, true, true, hold))
        assertFalse("not cut off", CommandFold.mustExpandBeforeAllow(true, false, false, hold))
        assertFalse("no command block", CommandFold.mustExpandBeforeAllow(false, true, false, hold))
        assertFalse("low risk keeps the plain tap", CommandFold.mustExpandBeforeAllow(true, true, false, ExtraConfirmationLevel.NONE))
    }
}
