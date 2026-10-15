package dev.agentnest.core.text

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DisplaySanitizerTest {
    @Test
    fun `plain text including korean and emoji is returned unchanged`() {
        val text = "npm test && echo 완료 🎉\n\tindented"
        val r = DisplaySanitizer.sanitize(text)
        assertSame(text, r.text)
        assertEquals(0, r.hiddenCount)
    }

    @Test
    fun `bidi overrides and isolates become visible escapes`() {
        val r = DisplaySanitizer.sanitize("echo safe ‮txt.sh.evil‬")
        assertEquals("echo safe ⟨U+202E⟩txt.sh.evil⟨U+202C⟩", r.text)
        assertEquals(2, r.hiddenCount)
        for (cp in listOf(0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)) {
            assertTrue(DisplaySanitizer.isHidden(cp), "U+" + cp.toString(16))
        }
    }

    @Test
    fun `zero width and other format characters are escaped`() {
        for (cp in listOf(0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x061C, 0xFEFF, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x00AD, 0x206A, 0xE0041)) {
            assertTrue(DisplaySanitizer.isHidden(cp), "U+" + cp.toString(16))
        }
        val r = DisplaySanitizer.sanitize("a​b﻿c")
        assertEquals("a⟨U+200B⟩b⟨U+FEFF⟩c", r.text)
        assertEquals(2, r.hiddenCount)
        // supplementary plane code points are escaped as one character
        val tag = DisplaySanitizer.sanitize("x" + String(Character.toChars(0xE0041)))
        assertEquals("x⟨U+E0041⟩", tag.text)
        assertEquals(1, tag.hiddenCount)
    }

    @Test
    fun `control characters other than newline and tab are escaped`() {
        val r = DisplaySanitizer.sanitize("a\rb\u0007c\u0085d e")
        assertEquals("a⟨U+000D⟩b⟨U+0007⟩c⟨U+0085⟩d⟨U+2028⟩e", r.text)
        assertEquals(4, r.hiddenCount)
    }

    @Test
    fun `blank filler letters and lone surrogates are escaped`() {
        assertEquals("⟨U+3164⟩", DisplaySanitizer.display("ㅤ"))
        assertEquals("⟨U+2800⟩", DisplaySanitizer.display("⠀"))
        assertEquals("⟨U+D800⟩", DisplaySanitizer.display("\uD800"))
    }

    @Test
    fun `null and empty are safe`() {
        assertEquals("", DisplaySanitizer.display(null))
        assertEquals(0, DisplaySanitizer.hiddenCount(""))
        assertFalse(DisplaySanitizer.isHidden('a'.code))
    }
}
