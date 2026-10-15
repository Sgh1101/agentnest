package dev.agentnest.app.notify

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context

/** Creates the five notification channels (docs/android.md 5). Safe to call on every start. */
object Channels {
    /** Registers all channels; Android keeps the user's per-channel settings once a channel exists. */
    fun create(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val channels = listOf(
            channel(ChannelIds.APPROVALS, "승인 요청", NotificationManager.IMPORTANCE_HIGH, "에이전트가 승인을 기다릴 때 바로 알려줘요", vibrate = true),
            quietApprovals(),
            channel(ChannelIds.ALERTS, "오류 알림", NotificationManager.IMPORTANCE_DEFAULT, "작업 실패, 테스트 실패 같은 문제를 알려줘요", vibrate = true),
            channel(ChannelIds.COMPLETIONS, "작업 완료", NotificationManager.IMPORTANCE_LOW, "오래 걸린 작업이 끝나면 조용히 알려줘요", vibrate = false),
            channel(ChannelIds.LINK, "연결 상태", NotificationManager.IMPORTANCE_MIN, "PC와의 연결 상태를 항상 보여줘요", vibrate = false),
            channel(ChannelIds.SECURITY, "보안 경고", NotificationManager.IMPORTANCE_HIGH, "PC 신원 변경, 기기 해제 같은 보안 문제를 알려줘요", vibrate = true),
        )
        manager.createNotificationChannels(channels)
    }

    /** Heads-up like `approvals`, but silent: used while the in-app sound setting is off. */
    private fun quietApprovals(): NotificationChannel {
        val channel = channel(ChannelIds.APPROVALS_QUIET, "승인 요청 (소리 없음)", NotificationManager.IMPORTANCE_HIGH, "소리와 진동 없이 승인 요청을 알려줘요", vibrate = false)
        channel.setSound(null, null)
        return channel
    }

    private fun channel(id: String, name: String, importance: Int, description: String, vibrate: Boolean): NotificationChannel {
        val channel = NotificationChannel(id, name, importance)
        channel.description = description
        channel.enableVibration(vibrate)
        channel.setShowBadge(false)
        // Details stay off the lock screen; each notification supplies a public version without them.
        channel.lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
        return channel
    }
}
