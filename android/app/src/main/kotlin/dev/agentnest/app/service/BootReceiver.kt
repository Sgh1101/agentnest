package dev.agentnest.app.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dev.agentnest.app.AgentNestApp
import kotlinx.coroutines.launch

/**
 * Optional auto-connect after boot (docs/android.md 3.1): only when the user switched it on and a pairing with a token
 * exists. `connectedDevice` foreground services may be started from BOOT_COMPLETED.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val app = context.applicationContext as? AgentNestApp ?: return
        val container = app.container
        val pending = goAsync()
        container.scope.launch {
            try {
                val enabled = container.settings.current().autoStartOnBoot
                val paired = container.pairingStore.load()?.sealedToken != null
                if (enabled && paired) container.startLinkService()
            } finally {
                pending.finish()
            }
        }
    }
}
