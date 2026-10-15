package dev.agentnest.core.link

/** How a replayable message relates to the last applied `seq` (protocol.md 8.2 / 8.4). */
enum class SeqVerdict {
    /** `seq == lastSeq + 1`: apply it. */
    APPLY,

    /** `seq <= lastSeq`: already applied (re-sent or replayed), skip it. */
    DUPLICATE,

    /** `seq > lastSeq + 1`: messages were missed; a snapshot is needed. */
    GAP,

    /** A snapshot is pending, so replayable messages are dropped until it arrives. */
    AWAITING_SNAPSHOT,
}

/** Pure `seq` classification. */
object SeqTracker {
    /** Classifies [seq] against [lastSeq]. While [awaitingSnapshot] is true nothing but a snapshot may be applied. */
    fun classify(lastSeq: Long, seq: Long, awaitingSnapshot: Boolean): SeqVerdict = when {
        awaitingSnapshot -> SeqVerdict.AWAITING_SNAPSHOT
        seq <= lastSeq -> SeqVerdict.DUPLICATE
        seq == lastSeq + 1 -> SeqVerdict.APPLY
        else -> SeqVerdict.GAP
    }
}
