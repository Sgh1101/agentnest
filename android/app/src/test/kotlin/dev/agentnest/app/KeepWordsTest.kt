package dev.agentnest.app

import dev.agentnest.app.ui.keepWords
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KeepWordsTest {
    private val wj = "\u2060"

    @Test
    fun hangulWordsAreJoinedButSpacesStayBreakable() {
        val out = "다시 연결해 주세요".keepWords()
        assertEquals("다${wj}시 연${wj}결${wj}해 주${wj}세${wj}요", out)
        assertEquals("다시 연결해 주세요", out.replace(wj, ""))
    }

    @Test
    fun asciiOnlyTextIsUntouchedSoLongPathsStillWrap() {
        val path = "C:\\Users\\dev\\agentnest\\android\\app\\build.gradle.kts"
        assertEquals(path, path.keepWords())
        assertEquals("a", "a".keepWords())
        assertEquals("", "".keepWords())
    }

    @Test
    fun digitsNextToHangulStayWithTheirParticleAndTheResultIsStable() {
        val out = "다른 2개는 대기 중".keepWords()
        assertTrue(out.contains("2${wj}개"))
        assertFalse(out.contains(" $wj"))
        assertFalse(out.contains("$wj "))
        assertEquals(out, out.keepWords())
    }
}
