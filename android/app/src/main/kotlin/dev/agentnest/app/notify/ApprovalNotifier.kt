package dev.agentnest.app.notify

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.app.NotificationCompat
import dev.agentnest.app.MainActivity
import dev.agentnest.app.R
import dev.agentnest.app.nav.DeepLink
import dev.agentnest.core.protocol.ApprovalRequest

/**
 * Heads-up notifications for pending approvals (docs/android.md 5). Title, risk level and remaining time only: no
 * command text anywhere, and a generic public version for the lock screen. There are NO inline allow/deny actions:
 * tapping opens the detail screen (deep link `agentnest://approval/{request_id}`), where authentication happens.
 */
class ApprovalNotifier(private val context: Context) {
    private val manager: NotificationManager? = context.getSystemService(NotificationManager::class.java)

    /** Posts (or updates) the notification of [request]. It disappears by itself when the card expires. */
    fun show(request: ApprovalRequest, remainingSeconds: Long, silent: Boolean) {
        if (remainingSeconds <= 0) return
        val text = NotificationTexts.approval(request, remainingSeconds)
        val channel = if (silent) ChannelIds.APPROVALS_QUIET else ChannelIds.APPROVALS
        val publicVersion = NotificationCompat.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_stat_kongi)
            .setContentTitle(NotificationTexts.APPROVAL_PUBLIC.title)
            .setContentText(NotificationTexts.APPROVAL_PUBLIC.body)
            .build()
        val notification: Notification = NotificationCompat.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_stat_kongi)
            .setContentTitle(text.title)
            .setContentText(text.body)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setTimeoutAfter(remainingSeconds * 1000L)
            .setGroup(GROUP)
            .setContentIntent(openDetail(request.requestId))
            .build()
        manager?.notify(request.requestId, NOTIFICATION_ID, notification)
    }

    /** Removes the notification of [requestId] (resolved, expired or opened in the app). */
    fun cancel(requestId: String) {
        manager?.cancel(requestId, NOTIFICATION_ID)
    }

    /** Keeps the group summary ("승인 대기 3건") in step with the number of posted notifications. */
    fun updateSummary(count: Int) {
        if (count < 2) {
            manager?.cancel(SUMMARY_ID)
            return
        }
        val text = NotificationTexts.approvalSummary(count)
        val summary = NotificationCompat.Builder(context, ChannelIds.APPROVALS)
            .setSmallIcon(R.drawable.ic_stat_kongi)
            .setContentTitle(text.title)
            .setContentText(text.body)
            .setGroup(GROUP)
            .setGroupSummary(true)
            .setSilent(true)
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setContentIntent(openApp())
            .build()
        manager?.notify(SUMMARY_ID, summary)
    }

    private fun openDetail(requestId: String): PendingIntent {
        val intent = Intent(context, MainActivity::class.java)
            .setAction(Intent.ACTION_VIEW)
            .setData(Uri.parse(DeepLink.forApproval(requestId)))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        return PendingIntent.getActivity(context, requestId.hashCode(), intent, FLAGS)
    }

    private fun openApp(): PendingIntent {
        val intent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        return PendingIntent.getActivity(context, SUMMARY_ID, intent, FLAGS)
    }

    private companion object {
        const val GROUP = "agentnest.approvals"
        const val NOTIFICATION_ID = 2001
        const val SUMMARY_ID = 2000
        const val FLAGS = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    }
}
