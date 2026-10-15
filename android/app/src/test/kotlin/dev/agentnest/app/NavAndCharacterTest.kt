package dev.agentnest.app

import dev.agentnest.app.character.KongiMotion
import dev.agentnest.app.character.KongiPose
import dev.agentnest.app.character.KongiSpec
import dev.agentnest.app.character.MotionLevel
import dev.agentnest.app.character.MotionPolicy
import dev.agentnest.app.character.Prop
import dev.agentnest.app.character.SystemMotion
import dev.agentnest.app.nav.DeepLink
import dev.agentnest.app.nav.NavState
import dev.agentnest.app.nav.Screen
import dev.agentnest.app.ui.Tone
import dev.agentnest.core.nest.Badge
import dev.agentnest.core.nest.KongiMood
import dev.agentnest.core.nest.TypingVariant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NavTest {
    @Test
    fun screensRoundTripThroughTheirSavedForm() {
        val all = listOf(
            Screen.Home, Screen.Agents, Screen.Projects, Screen.Activity, Screen.Settings, Screen.Approvals,
            Screen.ApprovalHistory, Screen.Pairing, Screen.Devices, Screen.Diagnostics,
            Screen.SessionDetail("claude_code:abc"), Screen.ApprovalDetail(TD.REQUEST_ID),
        )
        for (screen in all) assertEquals(screen, Screen.decode(screen.encode()))
        assertNull(Screen.decode("nope"))
        assertNull(Screen.decode("approval|"))
    }

    @Test
    fun deepLinkAcceptsOnlyWellFormedApprovalIds() {
        assertEquals(TD.REQUEST_ID, DeepLink.approvalId(DeepLink.forApproval(TD.REQUEST_ID)))
        assertEquals(TD.REQUEST_ID, DeepLink.approvalId("agentnest://approval/${TD.REQUEST_ID}/"))
        assertNull(DeepLink.approvalId(null))
        assertNull(DeepLink.approvalId("agentnest://approval/../../etc"))
        assertNull(DeepLink.approvalId("agentnest://pair?d=abc"))
        assertNull(DeepLink.approvalId("https://approval/${TD.REQUEST_ID}"))
        assertNull(DeepLink.approvalId("agentnest://approval/ar_short"))
    }

    @Test
    fun backStackBehaves() {
        val nav = NavState()
        assertEquals(Screen.Home, nav.current)
        assertFalse(nav.canGoBack)
        nav.selectTab(Screen.Settings)
        assertEquals(Screen.Settings, nav.current)
        assertTrue(nav.canGoBack)
        nav.push(Screen.Devices)
        assertEquals(Screen.Settings, nav.activeTab)
        nav.pop()
        nav.pop()
        assertEquals(Screen.Home, nav.current)
        nav.pop()
        assertEquals(Screen.Home, nav.current)
        nav.push(Screen.ApprovalDetail("x"))
        nav.push(Screen.ApprovalDetail("x"))
        assertEquals(listOf(Screen.Home, Screen.ApprovalDetail("x")), nav.stack)
        nav.resetTo(Screen.Home)
        assertEquals(listOf<Screen>(Screen.Home), nav.stack)
    }
}

class CharacterTest {
    @Test
    fun everyMoodHasASpecWithADescription() {
        for (mood in KongiMood.entries) {
            val spec = KongiSpec.of(mood, TypingVariant.WEAK, Badge.EXCLAMATION)
            assertTrue(spec.description.startsWith("콩이:"))
            assertTrue(spec.periodMs > 0)
        }
    }

    @Test
    fun moodSpecSnapshot() {
        assertEquals(Tone.WARNING, KongiSpec.of(KongiMood.RAISE_HAND, null, Badge.EXCLAMATION).tone)
        assertEquals("콩이: 승인을 기다리고 있어요", KongiSpec.of(KongiMood.RAISE_HAND, null, Badge.EXCLAMATION).description)
        assertEquals(Prop.HAND, KongiSpec.of(KongiMood.RAISE_HAND, null, Badge.QUESTION).prop)
        assertEquals(Badge.QUESTION, KongiSpec.of(KongiMood.RAISE_HAND, null, Badge.QUESTION).badge)
        assertEquals(Badge.NONE, KongiSpec.of(KongiMood.BLINK_SLOW, null, Badge.EXCLAMATION).badge)
        assertEquals(Prop.KEYBOARD, KongiSpec.of(KongiMood.TYPING, TypingVariant.FULL).prop)
        assertEquals(Prop.NONE, KongiSpec.of(KongiMood.TYPING, TypingVariant.WEAK).prop)
        assertEquals(120, KongiSpec.of(KongiMood.TYPING, TypingVariant.FULL).periodMs)
        assertEquals(250, KongiSpec.of(KongiMood.TYPING, TypingVariant.WEAK).periodMs)
        assertEquals(Prop.MAGNIFIER, KongiSpec.of(KongiMood.MAGNIFIER).prop)
        assertEquals(Prop.WRENCH, KongiSpec.of(KongiMood.TOOLS).prop)
        assertEquals(Prop.SWEAT, KongiSpec.of(KongiMood.FLUSTERED).prop)
        assertEquals(Prop.ZZZ, KongiSpec.of(KongiMood.SLEEPY).prop)
        assertEquals(Tone.SUCCESS, KongiSpec.of(KongiMood.CELEBRATE).tone)
        assertEquals(Tone.MUTED, KongiSpec.of(KongiMood.WORRIED).tone)
    }

    @Test
    fun poseIsDeterministicAndFiniteForEveryMoodAndLevel() {
        val a = KongiPose()
        val b = KongiPose()
        for (mood in KongiMood.entries) {
            val spec = KongiSpec.of(mood, TypingVariant.FULL, Badge.EXCLAMATION)
            for (level in MotionLevel.entries) {
                for (t in listOf(0L, 1L, 77L, 1234L, 99_999L)) {
                    KongiMotion.pose(spec, level, t, t, a)
                    KongiMotion.pose(spec, level, t, t, b)
                    assertEquals(a.bodyDy, b.bodyDy, 0f)
                    assertEquals(a.handRx, b.handRx, 0f)
                    assertTrue(a.bodyDy.isFinite() && a.eyeOpenL in 0f..1f && a.handLy.isFinite() && a.propAngle.isFinite())
                }
            }
        }
    }

    @Test
    fun stillLevelIgnoresTime() {
        val a = KongiPose()
        val b = KongiPose()
        val spec = KongiSpec.of(KongiMood.RAISE_HAND, null, Badge.EXCLAMATION)
        KongiMotion.pose(spec, MotionLevel.NONE, 0, 0, a)
        KongiMotion.pose(spec, MotionLevel.NONE, 987_654, 5, b)
        assertEquals(a.handRx, b.handRx, 0f)
        assertEquals(a.bodyDy, b.bodyDy, 0f)
    }

    @Test
    fun celebrateJumpsOnlyDuringTheFirstHalfSecond() {
        val spec = KongiSpec.of(KongiMood.CELEBRATE)
        val pose = KongiPose()
        KongiMotion.pose(spec, MotionLevel.FULL, 250, 250, pose)
        assertTrue(pose.bodyDy < -KongiMotion.JUMP_UNITS * 0.99f)
        KongiMotion.pose(spec, MotionLevel.FULL, 900, 900, pose)
        assertEquals(0f, pose.bodyDy, 0f)
        assertEquals(1f, pose.eyeHappy, 0f)
    }

    @Test
    fun blinkOnlyHappensNearTheEndOfAnInterval() {
        assertEquals(1f, KongiMotion.blinkFactor(1000), 0f)
        assertEquals(0f, KongiMotion.blinkFactor(3200 - 150), 0.001f)
        assertEquals(1f, KongiMotion.blinkFactor(3200), 0.001f)
        assertEquals(KongiMotion.blinkFactor(500), KongiMotion.blinkFactor(500 + 14_000), 0f)
    }

    @Test
    fun blendInterpolatesNumbersAndSwitchesDiscretePartsAtTheMidpoint() {
        val from = KongiPose().apply { bodyDy = 0f; prop = Prop.NONE }
        val to = KongiPose().apply { bodyDy = 10f; prop = Prop.WRENCH }
        val out = KongiPose()
        KongiMotion.blend(from, to, 0.25f, out)
        assertEquals(2.5f, out.bodyDy, 0.0001f)
        assertEquals(Prop.NONE, out.prop)
        KongiMotion.blend(from, to, 0.75f, out)
        assertEquals(Prop.WRENCH, out.prop)
    }

    @Test
    fun motionPolicyHonoursTheTogglesAndTheSystem() {
        assertEquals(MotionLevel.FULL, MotionPolicy.resolve(true, false, SystemMotion.NORMAL))
        assertEquals(MotionLevel.NONE, MotionPolicy.resolve(false, false, SystemMotion.NORMAL))
        assertEquals(MotionLevel.NONE, MotionPolicy.resolve(true, false, SystemMotion.DISABLED))
        assertEquals(MotionLevel.LOW, MotionPolicy.resolve(true, true, SystemMotion.NORMAL))
        assertEquals(MotionLevel.LOW, MotionPolicy.resolve(true, false, SystemMotion.POWER_SAVE))
        assertEquals(MotionLevel.NONE, MotionPolicy.resolve(false, true, SystemMotion.POWER_SAVE))
    }
}
