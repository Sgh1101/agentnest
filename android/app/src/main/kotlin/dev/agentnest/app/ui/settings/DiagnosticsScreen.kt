package dev.agentnest.app.ui.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.agentnest.app.data.PairedInfo
import dev.agentnest.app.ui.S
import dev.agentnest.app.ui.common.KeyValueRow
import dev.agentnest.app.ui.common.ScreenHeader
import dev.agentnest.core.link.LinkState
import dev.agentnest.core.nest.NestState
import dev.agentnest.core.text.RelativeTime
import java.time.Instant

/** One diagnostics line. */
data class DiagLine(val label: String, val value: String)

/**
 * Pure builder of the diagnostics lines. It only reports state names, counts and versions: never tokens, pins, nonces
 * or command text. Unit-tested.
 */
object Diagnostics {
    fun lines(nest: NestState, paired: PairedInfo?, now: Instant): List<DiagLine> {
        val out = ArrayList<DiagLine>()
        out += DiagLine(S.DIAG_LINK, linkName(nest.link))
        (nest.link as? LinkState.Connected)?.let { c ->
            out += DiagLine(S.DIAG_RTT, c.rttMs?.let { "$it ms" } ?: "-")
        }
        out += DiagLine(S.DIAG_PC, nest.pc?.let { "${it.name} (${it.appVersion})" } ?: "-")
        out += DiagLine(S.DIAG_SESSIONS, nest.sessions.size.toString())
        out += DiagLine(S.DIAG_APPROVALS, nest.approvals.size.toString())
        out += DiagLine(S.DIAG_LAST_SEQ, nest.lastSeq.toString())
        out += DiagLine(S.DIAG_SKEW, "${nest.clockSkewMs} ms")
        out += DiagLine(S.DIAG_LAST_SYNC, nest.lastSyncAt?.let { RelativeTime.ago(it, now) } ?: "-")
        out += DiagLine(S.DIAG_FROM_CACHE, if (nest.fromCache) S.YES else S.NO)
        out += DiagLine(S.DIAG_RESYNC, if (nest.resync.awaitingSnapshot) S.YES else S.NO)
        nest.welcome?.let { w ->
            out += DiagLine(S.DIAG_PROTOCOL, "v${w.protocol.version}.${w.protocol.minor}")
            out += DiagLine(S.DIAG_CAPABILITIES, w.capabilities.joinToString(", "))
            out += DiagLine(S.DIAG_TTL, "${w.limits.approvalTtlS} s")
        }
        out += DiagLine(S.DIAG_HOSTS, paired?.hosts?.size?.toString() ?: "0")
        nest.lastError?.let { out += DiagLine(S.DIAG_LAST_ERROR, it.code) }
        return out
    }

    /** Names the link state without any payload. */
    fun linkName(link: LinkState): String = when (link) {
        LinkState.Unpaired -> "Unpaired"
        is LinkState.Connecting -> "Connecting (attempt ${link.attempt})"
        LinkState.Challenged -> "Challenged"
        is LinkState.Connected -> "Connected"
        is LinkState.Reconnecting -> "Reconnecting (attempt ${link.attempt})"
        LinkState.Offline -> "Offline"
        is LinkState.PcUnreachable -> "PcUnreachable"
        is LinkState.NeedsRepair -> "NeedsRepair (${link.reason})"
        is LinkState.Revoked -> "Revoked (${link.code})"
        is LinkState.Suspended -> "Suspended"
        LinkState.Incompatible -> "Incompatible"
    }
}

/** Diagnostics screen (docs/android.md 2.3, settings). */
@Composable
fun DiagnosticsScreen(nest: NestState, paired: PairedInfo?, now: Instant, onBack: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(bottom = 16.dp),
    ) {
        ScreenHeader(title = S.DIAGNOSTICS, onBack = onBack)
        Text(S.DIAG_HELP, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
        for (line in Diagnostics.lines(nest, paired, now)) {
            KeyValueRow(line.label, line.value)
        }
    }
}
