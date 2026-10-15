package dev.agentnest.core.text

/** Result of [DisplaySanitizer.sanitize]: the text to render and how many invisible characters were replaced. */
data class SanitizedText(val text: String, val hiddenCount: Int)

/**
 * Makes agent-supplied text safe to show next to an Allow button (security.md 6.1, docs/android.md 2.2).
 *
 * Bidirectional controls (U+202A-202E, U+2066-2069), zero-width and other format characters (Unicode category Cf:
 * U+200B-200F, U+061C, U+FEFF, U+2060-2064, ...), control characters other than line feed and tab, line/paragraph
 * separators, lone surrogates and the blank "filler" letters (Hangul fillers, braille blank) are replaced by a
 * visible escape such as `⟨U+202E⟩`. The text on screen then cannot differ from what the PC hashed in a way the user
 * cannot see. Pure and allocation-light; it never changes visible characters.
 */
object DisplaySanitizer {
    /** Characters that render as nothing (or reorder text) although they are not in the categories above. */
    private val extraInvisible = intArrayOf(0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x180E, 0x034F)

    /** True when [codePoint] must not be rendered as is. */
    fun isHidden(codePoint: Int): Boolean {
        if (codePoint == '\n'.code || codePoint == '\t'.code) return false
        return when (Character.getType(codePoint).toByte()) {
            Character.FORMAT, Character.CONTROL, Character.SURROGATE, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR -> true
            else -> codePoint in extraInvisible
        }
    }

    /** Returns [text] with every hidden character replaced by its `⟨U+XXXX⟩` escape. Null maps to the empty string. */
    fun sanitize(text: String?): SanitizedText {
        if (text.isNullOrEmpty()) return SanitizedText("", 0)
        var first = -1
        var i = 0
        while (i < text.length) {
            val cp = text.codePointAt(i)
            if (isHidden(cp)) {
                first = i
                break
            }
            i += Character.charCount(cp)
        }
        if (first < 0) return SanitizedText(text, 0)
        val sb = StringBuilder(text.length + 16)
        sb.append(text, 0, first)
        var count = 0
        i = first
        while (i < text.length) {
            val cp = text.codePointAt(i)
            i += Character.charCount(cp)
            if (isHidden(cp)) {
                count++
                sb.append(escape(cp))
            } else {
                sb.appendCodePoint(cp)
            }
        }
        return SanitizedText(sb.toString(), count)
    }

    /** Shortcut for UI code: the escaped text only. */
    fun display(text: String?): String = sanitize(text).text

    /** Number of hidden characters in [text]. */
    fun hiddenCount(text: String?): Int = sanitize(text).hiddenCount

    /** The visible escape of one code point, e.g. `⟨U+202E⟩`. */
    fun escape(codePoint: Int): String = "⟨U+" + Integer.toHexString(codePoint).uppercase().padStart(4, '0') + "⟩"
}
