package dev.agentnest.core.protocol

import dev.agentnest.core.crypto.B64

/**
 * The four fields that bind a decision to one approval (protocol.md 6.1 / 6.2). They are echoed verbatim from the
 * card; two cards with the same `request_id` but a different binding are NEVER the same request.
 */
data class ApprovalBinding(
    val requestId: String,
    val sessionKey: String,
    val nonceB64: String,
    val toolInputSha256: String,
) {
    companion object {
        private val REQUEST_ID = Regex("^ar_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        private val SHA256_HEX = Regex("^[0-9a-f]{64}$")
        private const val NONCE_BYTES = 16

        /** The binding of [request]. */
        fun of(request: ApprovalRequest): ApprovalBinding =
            ApprovalBinding(request.requestId, request.sessionKey, request.nonceB64, request.toolInputSha256)

        /** Why [requestId] is not a valid `ar_` + UUIDv7 id, or null. */
        fun requestIdProblem(requestId: String): String? =
            if (REQUEST_ID.matches(requestId)) null else "malformed request_id"

        /** Why the binding fields are malformed (null when they are well formed). */
        fun problem(requestId: String, sessionKey: String, nonceB64: String, toolInputSha256: String): String? = when {
            !REQUEST_ID.matches(requestId) -> "malformed request_id"
            sessionKey.isEmpty() -> "empty session_key"
            !SHA256_HEX.matches(toolInputSha256) -> "tool_input_sha256 must be lowercase hex"
            B64.decode(nonceB64)?.size != NONCE_BYTES -> "nonce_b64 must be 16 bytes"
            else -> null
        }

        /** Why [request] has a malformed binding, or null. */
        fun problem(request: ApprovalRequest): String? =
            problem(request.requestId, request.sessionKey, request.nonceB64, request.toolInputSha256)
    }
}
