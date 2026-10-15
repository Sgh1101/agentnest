package dev.agentnest.app.notify

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import dev.agentnest.app.MainActivity
import dev.agentnest.app.R
import dev.agentnest.core.link.SecurityAlertKind

/** Error, completion and security notifications (docs/android.md 5). Wording comes from [NotificationTexts]. */
class AlertNotifier(private val context: Context) {
    private val manager: NotificationManager? = context.getSystemService(NotificationManager::class.java)

    /** An error alert for [sessionKey]; a newer one replaces the older one of the same session. */
    fun error(text: NotificationText, sessionKey: String) {
        post(ChannelIds.ALERTS, sessionKey, ALERT_ID, text, NotificationCompat.PRIORITY_DEFAULT, silent = false)
    }

    /** A completion notice for a long turn (low importance, no sound). */
    fun completion(text: NotificationText, sessionKey: String) {
        post(ChannelIds.COMPLETIONS, sessionKey, COMPLETION_ID, text, NotificationCompat.PRIORITY_LOW, silent = true)
    }

    /** A security warning (PC identity changed, device revoked, repeated auth failures). */
    fun security(kind: SecurityAlertKind) {
        post(ChannelIds.SECURITY, null, SECURITY_ID_BASE + kind.ordinal, NotificationTexts.security(kind), NotificationCompat.PRIORITY_HIGH, silent = false)
    }

    /** The link service could not start in the foreground (Android 12+ background restrictions). */
    fun serviceStartBlocked() {
        post(
            ChannelIds.ALERTS,
            null,
            SERVICE_BLOCKED_ID,
            NotificationText("연결을 시작하지 못했어요", "앱을 열어 '다시 연결'을 눌러 주세요"),
            NotificationCompat.PRIORITY_DEFAULT,
            silent = false,
        )
    }

    private fun post(channel: String, tag: String?, id: Int, text: NotificationText, priority: Int, silent: Boolean) {
        val open = PendingIntent.getActivity(
            context,
            id,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val publicVersion = NotificationCompat.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_stat_kongi)
            .setContentTitle("AgentNest")
            .setContentText("새 알림이 있어요")
            .build()
        val notification = NotificationCompat.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_stat_kongi)
            .setContentTitle(text.title)
            .setContentText(text.body)
            .setPriority(priority)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .setAutoCancel(true)
            .setSilent(silent)
            .setContentIntent(open)
            .build()
        manager?.notify(tag, id, notification)
    }

    private companion object {
        const val ALERT_ID = 3001
        const val COMPLETION_ID = 3002
        const val SERVICE_BLOCKED_ID = 3003
        const val SECURITY_ID_BASE = 4000
    }
}
