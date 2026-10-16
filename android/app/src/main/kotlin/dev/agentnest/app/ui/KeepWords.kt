package dev.agentnest.app.ui

private const val WORD_JOINER = '\u2060'

private fun isHangul(c: Char): Boolean = c in '\uAC00'..'\uD7A3' || c in '\u1100'..'\u11FF' || c in '\u3130'..'\u318F'

/**
 * Display-only "keep-all" for Korean prose: Android breaks a Hangul line between any two syllables ("주세/요"); a word
 * joiner next to Hangul makes a line break only at spaces. Used for fixed UI sentences and the PC-written headline, never
 * for anything the user has to read faithfully before approving (commands, paths, file names, card bodies): those must
 * not get a single extra invisible character.
 */
fun String.keepWords(): String {
    if (length < 2) return this
    val out = StringBuilder(length + length / 2)
    for (i in indices) {
        val c = this[i]
        if (i > 0) {
            val p = this[i - 1]
            if (!p.isWhitespace() && !c.isWhitespace() && p != WORD_JOINER && c != WORD_JOINER && (isHangul(p) || isHangul(c))) {
                out.append(WORD_JOINER)
            }
        }
        out.append(c)
    }
    return out.toString()
}
