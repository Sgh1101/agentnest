package dev.agentnest.app.ui.approvals

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.agentnest.app.ui.S
import dev.agentnest.core.approval.ApprovalDisplay
import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.text.DisplaySanitizer
import dev.agentnest.app.ui.common.HiddenCharsChip
import dev.agentnest.app.ui.common.SecureDialogWindow

/**
 * The re-confirmation step for risky approvals (docs/android.md 2.2): shows the FULL command again and asks the user
 * to tick "내용을 확인했어요" ([needCheckbox]); when [needHold] the confirm button is a hold-to-confirm button.
 */
@Composable
fun ExtraConfirmDialog(
    request: ApprovalRequest,
    needHold: Boolean,
    needCheckbox: Boolean,
    onConfirmed: () -> Unit,
    onDismiss: () -> Unit,
) {
    var checked by remember { mutableStateOf(false) }
    val ready = !needCheckbox || checked
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(S.EXTRA_CONFIRM_TITLE) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SecureDialogWindow(secure = true)
                Text(S.EXTRA_CONFIRM_BODY, style = MaterialTheme.typography.bodyMedium)
                HiddenCharsChip(ApprovalDisplay.hiddenCharCount(request))
                if (needCheckbox) {
                    Text(
                        text = DisplaySanitizer.display(request.details.command ?: request.title),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier
                            .heightIn(max = 220.dp)
                            .verticalScroll(rememberScrollState()),
                    )
                    request.details.filePaths.take(5).forEach {
                        Text(DisplaySanitizer.display(it), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = checked, onCheckedChange = { checked = it })
                        Text(S.EXTRA_CONFIRM_CHECK, modifier = Modifier.padding(start = 4.dp))
                    }
                }
            }
        },
        confirmButton = {
            if (needHold) {
                HoldToConfirmButton(label = S.HOLD_TO_CONFIRM, enabled = ready, onConfirmed = onConfirmed)
            } else {
                TextButton(onClick = onConfirmed, enabled = ready) { Text(S.CONFIRM) }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(S.CANCEL) } },
    )
}
