package dev.agentnest.app.ui.approvals

import dev.agentnest.core.protocol.ExtraConfirmationLevel

/**
 * Pure rules for the folded command block of the approval detail (docs/android.md 2.2). The block shows 4 lines
 * and an expand button; whether the text really is cut off is only known after layout (`hasVisualOverflow`), because
 * a large font or a narrow window cuts even a short command.
 */
object CommandFold {
    /** Number of lines shown while folded. */
    const val FOLDED_LINES: Int = 4

    /** Cheap pre-layout guess: a long or many-line command probably needs the expand button. */
    fun looksLong(text: String): Boolean = text.length > 120 || text.count { it == '\n' } >= FOLDED_LINES

    /**
     * The expand / collapse button is shown when the text is probably long, when layout says it is clipped, and always
     * while expanded (so it can be folded again).
     */
    fun showToggle(text: String, clippedByLayout: Boolean, expanded: Boolean): Boolean =
        expanded || clippedByLayout || looksLong(text)

    /**
     * True when the user must expand the command before an allow-type decision may start: there is a command block,
     * it is visibly cut off, it has not been expanded, and the decision needs extra confirmation (high / critical risk
     * or hidden characters). A command that is cut off must not be approved on the strength of a prefix.
     */
    fun mustExpandBeforeAllow(
        hasCommandBlock: Boolean,
        clippedByLayout: Boolean,
        expanded: Boolean,
        extraConfirmation: ExtraConfirmationLevel,
    ): Boolean = hasCommandBlock && clippedByLayout && !expanded && extraConfirmation.effective != ExtraConfirmationLevel.NONE
}
