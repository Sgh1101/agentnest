package dev.agentnest.core.util

import java.security.SecureRandom

/** Generates lowercase UUIDv7 strings (`xxxxxxxx-xxxx-7xxx-[89ab]xxx-xxxxxxxxxxxx`) for envelope ids. */
class Uuid7Generator(
    private val millis: () -> Long = System::currentTimeMillis,
    private val random: java.util.Random = SecureRandom(),
) {
    /** Returns a new UUIDv7 using the current time source. */
    fun next(): String {
        val ts = millis() and 0xFFFF_FFFF_FFFFL
        val randA = random.nextInt(1 shl 12).toLong()
        val randB = random.nextLong()
        val msb = (ts shl 16) or (0x7L shl 12) or randA
        val lsb = (randB and 0x3FFF_FFFF_FFFF_FFFFL) or (0x2L shl 62)
        return format(msb, lsb)
    }

    private fun format(msb: Long, lsb: Long): String {
        fun hex(value: Long, digits: Int): String = java.lang.Long.toHexString(value or (1L shl (4 * digits))).substring(1)
        return hex(msb ushr 32, 8) + "-" + hex((msb ushr 16) and 0xFFFF, 4) + "-" + hex(msb and 0xFFFF, 4) + "-" +
            hex((lsb ushr 48) and 0xFFFF, 4) + "-" + hex(lsb and 0xFFFF_FFFF_FFFFL, 12)
    }
}
