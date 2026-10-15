package dev.agentnest.app.notify

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import dev.agentnest.app.MainActivity
import dev.agentnest.app.R
import dev.agentnest.app.service.LinkService

/** The persistent low-importance status notification of the foreground service (docs/android.md 5, `link` channel). */
class LinkNotifier(private val context: Context) {
    private val manager: NotificationManager? = context.getSystemService(NotificationManager::class.java)
    private var lastText: String? = null

    /** Builds the notification for [text] ("연결됨 · DESKTOP-HOME", "다시 연결 중 ...", "오프라인"). */
    fun build(text: String): Notification {
        lastText = text
        val open = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val reconnect = PendingIntent.getService(
            context,
            1,
            Intent(context, LinkService::class.java).setAction(LinkService.ACTION_RECONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val pause = PendingIntent.getService(
            context,
            2,
            Intent(context, LinkService::class.java).setAction(LinkService.ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(context, ChannelIds.LINK)
            .setSmallIcon(R.drawable.ic_stat_kongi)
            .setContentTitle("AgentNest")
            .setContentText(text)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setSilent(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setContentIntent(open)
            .addAction(0, "다시 연결", reconnect)
            .addAction(0, "일시정지", pause)
            .build()
    }

    /** Replaces the text when it changed. */
    fun update(text: String) {
        if (text == lastText) return
        manager?.notify(NOTIFICATION_ID, build(text))
    }

    companion object {
        /** Notification id of the foreground service (must not be 0). */
        const val NOTIFICATION_ID = 1001
    }
}
