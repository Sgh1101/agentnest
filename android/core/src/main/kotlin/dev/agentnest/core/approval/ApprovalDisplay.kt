package dev.agentnest.core.approval

import dev.agentnest.core.protocol.ApprovalRequest
import dev.agentnest.core.text.DisplaySanitizer

/** What the UI shows of an approval after display sanitisation (one place, so every screen agrees). */
object ApprovalDisplay {
    /**
     * Number of hidden / direction-changing characters in everything the user reads before allowing: title, command,
     * working directory, file paths, previews, MCP server, project (name, branch, path hint), the agent label, the
     * Korean risk reasons and the agent's purpose text.
     */
    fun hiddenCharCount(request: ApprovalRequest): Int {
        val d = request.details
        var total = 0
        for (text in listOf(
            request.title,
            d.command,
            d.cwdHint,
            d.diffPreview,
            d.contentPreview,
            d.mcpServer,
            request.purpose,
            request.agentLabel,
            request.project.name,
            request.project.branch,
            request.project.pathHint,
        )) {
            total += DisplaySanitizer.hiddenCount(text)
        }
        for (path in d.filePaths) total += DisplaySanitizer.hiddenCount(path)
        for (reason in request.risk.reasonsKo) total += DisplaySanitizer.hiddenCount(reason)
        return total
    }
}
