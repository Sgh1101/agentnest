package dev.agentnest.app.nav

/**
 * Destinations of the manual navigation (docs/android.md 1.1: sealed class + BackHandler, no Navigation library).
 * [encode]/[decode] make the stack survive configuration changes and process death.
 */
sealed interface Screen {
    data object Home : Screen
    data object Agents : Screen
    data object Projects : Screen
    data object Activity : Screen
    data object Settings : Screen
    data object Approvals : Screen
    data object ApprovalHistory : Screen
    data object Pairing : Screen
    data object Devices : Screen
    data object Diagnostics : Screen
    data class SessionDetail(val sessionKey: String) : Screen
    data class ApprovalDetail(val requestId: String) : Screen

    /** True for the five bottom-bar destinations. */
    val isTab: Boolean get() = this is Home || this is Agents || this is Projects || this is Activity || this is Settings

    /** Stable text form used by the saved-state saver. */
    fun encode(): String = when (this) {
        Home -> "home"
        Agents -> "agents"
        Projects -> "projects"
        Activity -> "activity"
        Settings -> "settings"
        Approvals -> "approvals"
        ApprovalHistory -> "history"
        Pairing -> "pairing"
        Devices -> "devices"
        Diagnostics -> "diagnostics"
        is SessionDetail -> "session|$sessionKey"
        is ApprovalDetail -> "approval|$requestId"
    }

    companion object {
        /** Inverse of [encode]; null for unknown text. */
        fun decode(text: String): Screen? = when {
            text == "home" -> Home
            text == "agents" -> Agents
            text == "projects" -> Projects
            text == "activity" -> Activity
            text == "settings" -> Settings
            text == "approvals" -> Approvals
            text == "history" -> ApprovalHistory
            text == "pairing" -> Pairing
            text == "devices" -> Devices
            text == "diagnostics" -> Diagnostics
            text.startsWith("session|") && text.length > "session|".length -> SessionDetail(text.removePrefix("session|"))
            text.startsWith("approval|") && text.length > "approval|".length -> ApprovalDetail(text.removePrefix("approval|"))
            else -> null
        }
    }
}

/** Parser of the notification deep link `agentnest://approval/{request_id}` (docs/android.md 5). */
object DeepLink {
    private const val PREFIX = "agentnest://approval/"
    private val REQUEST_ID = Regex("^ar_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    /** Builds the link for [requestId]. */
    fun forApproval(requestId: String): String = PREFIX + requestId

    /** The request id of a deep link, or null when [uri] is not an approval link or the id is malformed. */
    fun approvalId(uri: String?): String? {
        if (uri == null || !uri.startsWith(PREFIX)) return null
        val id = uri.removePrefix(PREFIX).trimEnd('/')
        return id.takeIf { REQUEST_ID.matches(it) }
    }
}
