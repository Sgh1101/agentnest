package dev.agentnest.core.link

import dev.agentnest.core.protocol.AgentEvent
import dev.agentnest.core.protocol.EventKind
import dev.agentnest.core.protocol.EventsPageMessage
import dev.agentnest.core.protocol.EventsRequestMessage
import dev.agentnest.core.protocol.EventsRequestPayload
import dev.agentnest.core.protocol.FrameMeta
import dev.agentnest.core.protocol.Ts
import java.time.Instant

/**
 * Pages through history with `events_request` / `events_page` (protocol.md 4.15). Immutable; every call
 * returns a new pager. `before_seq` is exclusive; the first request uses `snapshot.seq + 1`.
 */
data class EventsPager(
    val sessionKey: String? = null,
    val kinds: List<EventKind>? = null,
    val events: List<AgentEvent> = emptyList(),
    val hasMore: Boolean = true,
    val nextBeforeSeq: Long? = null,
    val detailOmitted: Boolean = false,
    val pendingRequestId: String? = null,
) {
    /** True while a request is in flight. */
    val loading: Boolean get() = pendingRequestId != null

    /** Result of starting a request. [message] is null when nothing should be sent. */
    data class Started(val pager: EventsPager, val message: EventsRequestMessage?)

    /**
     * Prepares the next request. [firstPageBeforeSeq] (normally `lastSeq + 1`) is used until a page told us
     * `next_before_seq`. Nothing is sent while a request is pending or when there is no more history.
     */
    fun next(firstPageBeforeSeq: Long, limit: Int, requestId: String, now: Instant): Started {
        if (loading || !hasMore) return Started(this, null)
        val boundedKinds = kinds?.filter { it != EventKind.UNKNOWN }?.take(MAX_KINDS)
        val message = EventsRequestMessage(
            FrameMeta(requestId, Ts.of(now)),
            EventsRequestPayload(
                sessionKey = sessionKey,
                beforeSeq = nextBeforeSeq ?: firstPageBeforeSeq,
                limit = limit.coerceIn(1, MAX_LIMIT),
                kinds = boundedKinds,
            ),
        )
        return Started(copy(pendingRequestId = requestId), message)
    }

    /** Applies a page. Pages answering a different request are ignored. Events are merged by `seq`. */
    fun onPage(page: EventsPageMessage): EventsPager {
        if (page.payload.inReplyTo != pendingRequestId) return this
        val merged = (events + page.payload.events).associateBy { it.seq }.values.sortedBy { it.seq }
        return copy(
            events = merged,
            hasMore = page.payload.hasMore,
            nextBeforeSeq = page.payload.nextBeforeSeq,
            detailOmitted = detailOmitted || page.payload.detailOmitted,
            pendingRequestId = null,
        )
    }

    /** Drops the pending request (e.g. the link went down); a later [next] may retry. */
    fun cancelPending(): EventsPager = copy(pendingRequestId = null)

    companion object {
        const val MAX_LIMIT = 100
        const val MAX_KINDS = 16
    }
}
