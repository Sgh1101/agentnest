package dev.agentnest.core.link

import dev.agentnest.core.crypto.B64
import dev.agentnest.core.crypto.Canonical
import dev.agentnest.core.crypto.PairingCrypto
import dev.agentnest.core.crypto.SpkiPin
import dev.agentnest.core.protocol.ChallengeMessage
import dev.agentnest.core.protocol.ClientMessage
import dev.agentnest.core.protocol.DeviceInfo
import dev.agentnest.core.protocol.ErrorMessage
import dev.agentnest.core.protocol.FrameMeta
import dev.agentnest.core.protocol.PairMessage
import dev.agentnest.core.protocol.PairPayload
import dev.agentnest.core.protocol.PairPendingMessage
import dev.agentnest.core.protocol.PairResultMessage
import dev.agentnest.core.protocol.PcInfo
import dev.agentnest.core.protocol.QrPayload
import dev.agentnest.core.protocol.ServerMessage
import dev.agentnest.core.protocol.Ts
import dev.agentnest.core.protocol.UnpairMessage
import dev.agentnest.core.protocol.UnpairPayload
import dev.agentnest.core.util.Uuid7Generator
import java.time.Duration
import java.time.Instant

/** What the phone knows about itself while pairing. [name] is NFC-normalised and cut to 64 UTF-8 bytes. */
data class DeviceDescriptor(
    val name: String,
    val model: String? = null,
    val osVersion: String? = null,
    val appVersion: String? = null,
)

/** Why a pairing attempt ended without success. [messageKo] is the user-facing text. */
enum class PairingFailure(val messageKo: String) {
    PC_ID_MISMATCH("QR의 PC와 연결된 PC가 달라요. 페어링을 중단했어요"),
    BAD_CHALLENGE("PC가 보낸 데이터가 올바르지 않아요. 다시 시도해 주세요"),
    SAS_MISMATCH("PC에서 받은 확인 숫자가 달라요. 페어링을 중단했어요"),
    PAIR_FAILED("페어링하지 못했어요. PC에서 QR을 다시 만들어 주세요"),
    PAIR_REJECTED("PC에서 거절했어요"),
    PAIR_BUSY("PC에서 다른 요청을 먼저 처리하세요"),
    TIMEOUT("PC에서 승인하지 않아 페어링이 끝났어요"),
    PROTOCOL("PC와 통신하지 못했어요. 다시 시도해 주세요"),
    CONNECTION_LOST("PC와 연결이 끊겼어요. 다시 시도해 주세요"),
    CANCELLED("페어링을 취소했어요"),
}

/** Successful pairing outcome. [deviceToken] is a secret: store it only through the Keystore vault. */
class PairingResult(
    val deviceId: String,
    val deviceToken: String,
    val pc: PcInfo,
    val pin: SpkiPin,
    val hosts: HostBookState,
) {
    override fun toString(): String = "PairingResult(deviceId=$deviceId, pc=${pc.pcId}, token=<redacted>)"
}

/** Where a [PairingFlow] currently is. */
sealed interface PairingPhase {
    data object WaitingForChallenge : PairingPhase
    data object WaitingForPairPending : PairingPhase

    /** The phone-computed [sas] is on screen; the user must press [Approve] on the PC. */
    data class ShowingSas(val sas: String, val deadline: Instant) : PairingPhase
    data class Completed(val result: PairingResult) : PairingPhase
    data class Failed(val failure: PairingFailure) : PairingPhase
}

/** Effects requested by [PairingFlow]. */
sealed interface PairingEffect {
    data class Send(val message: ClientMessage) : PairingEffect
    data class Close(val code: Int, val reason: String) : PairingEffect

    /** Show this phone-computed SAS together with "PC에서 승인을 눌러 주세요". */
    data class ShowSas(val sas: String) : PairingEffect
    data class Completed(val result: PairingResult) : PairingEffect
    data class Failed(val failure: PairingFailure) : PairingEffect
}

/**
 * Phone side of pairing (protocol.md 4.2/4.3, security.md 4.2). Pure state machine over server messages:
 * answers `challenge` with `pair` (HMAC possession proof), computes the SAS locally and compares it with
 * `pair_pending.sas` in constant time, and aborts with `unpair{pairing_id}` on any mismatch. The pairing secret
 * is wiped on every terminal path. Never display the PC-sent SAS.
 */
class PairingFlow(
    private val qr: QrPayload,
    private val device: DeviceDescriptor,
    private val devicePublicKeySpki: ByteArray?,
    private val ids: () -> String = Uuid7Generator()::next,
    private val confirmGrace: Duration = Duration.ofSeconds(5),
) {
    /** Current phase. */
    var phase: PairingPhase = PairingPhase.WaitingForChallenge
        private set

    private var challenge: ByteArray? = null

    private val terminal: Boolean get() = phase is PairingPhase.Completed || phase is PairingPhase.Failed

    /** Handles one server frame received during pairing. */
    fun onMessage(message: ServerMessage, now: Instant): List<PairingEffect> {
        if (terminal) return emptyList()
        return when (message) {
            is ChallengeMessage -> onChallenge(message, now)
            is PairPendingMessage -> onPairPending(message, now)
            is PairResultMessage -> onPairResult(message, now)
            is ErrorMessage -> fail(failureForError(message.payload.code), emptyList())
            else -> fail(PairingFailure.PROTOCOL, listOf(PairingEffect.Close(CLOSE_NORMAL, "unexpected message")))
        }
    }

    /** The socket was closed or failed. Ends the flow unless it already finished. */
    fun onConnectionClosed(): List<PairingEffect> = if (terminal) emptyList() else fail(PairingFailure.CONNECTION_LOST, emptyList())

    /** Periodic call: ends the flow when the PC never approved in time. */
    fun onTick(now: Instant): List<PairingEffect> {
        val current = phase
        if (current is PairingPhase.ShowingSas && now.isAfter(current.deadline)) {
            return fail(
                PairingFailure.TIMEOUT,
                listOf(
                    PairingEffect.Send(unpair(now)),
                    PairingEffect.Close(CLOSE_NORMAL, "pair confirm timeout"),
                ),
            )
        }
        return emptyList()
    }

    /** The user left the pairing screen. */
    fun cancel(now: Instant): List<PairingEffect> {
        if (terminal) return emptyList()
        val effects = mutableListOf<PairingEffect>()
        if (phase !is PairingPhase.WaitingForChallenge) effects += PairingEffect.Send(unpair(now))
        effects += PairingEffect.Close(CLOSE_NORMAL, "cancelled")
        return fail(PairingFailure.CANCELLED, effects)
    }

    private fun onChallenge(message: ChallengeMessage, now: Instant): List<PairingEffect> {
        if (phase != PairingPhase.WaitingForChallenge) return fail(PairingFailure.PROTOCOL, listOf(close("duplicate challenge")))
        if (message.payload.pcId != qr.pcId) return fail(PairingFailure.PC_ID_MISMATCH, listOf(close("pc id mismatch")))
        val raw = B64.decode(message.payload.challengeB64)
        if (raw == null || raw.size != Canonical.CHALLENGE_BYTES) return fail(PairingFailure.BAD_CHALLENGE, listOf(close("bad challenge")))
        challenge = raw
        val name = Canonical.fitDeviceName(device.name)
        val proof = PairingCrypto.proof(qr.secret, qr.pcId, qr.pairingId, raw, name, devicePublicKeySpki)
        val pair = PairMessage(
            FrameMeta(ids(), Ts.of(now)),
            PairPayload(
                pairingId = qr.pairingId,
                challengeB64 = message.payload.challengeB64,
                device = DeviceInfo(name, "android", device.model, device.osVersion, device.appVersion),
                devicePubkeySpkiB64 = devicePublicKeySpki?.let(B64::encode),
                proofB64 = B64.encode(proof),
                protocol = 1,
            ),
        )
        phase = PairingPhase.WaitingForPairPending
        return listOf(PairingEffect.Send(pair))
    }

    private fun onPairPending(message: PairPendingMessage, now: Instant): List<PairingEffect> {
        val raw = challenge
        if (phase != PairingPhase.WaitingForPairPending || raw == null || message.payload.pairingId != qr.pairingId) {
            return fail(PairingFailure.PROTOCOL, listOf(close("unexpected pair_pending")))
        }
        val computed = PairingCrypto.sas(qr.secret, raw, devicePublicKeySpki)
        if (!PairingCrypto.sasEquals(computed, message.payload.sas)) {
            return fail(
                PairingFailure.SAS_MISMATCH,
                listOf(PairingEffect.Send(unpair(now)), close("sas mismatch")),
            )
        }
        val deadline = now.plusMillis(message.payload.confirmTimeoutMs).plus(confirmGrace)
        phase = PairingPhase.ShowingSas(computed, deadline)
        return listOf(PairingEffect.ShowSas(computed))
    }

    private fun onPairResult(message: PairResultMessage, now: Instant): List<PairingEffect> {
        val payload = message.payload
        if (phase !is PairingPhase.ShowingSas && phase != PairingPhase.WaitingForPairPending) {
            return fail(PairingFailure.PROTOCOL, listOf(close("unexpected pair_result")))
        }
        if (!payload.ok) return fail(failureForError(payload.errorCode ?: ""), emptyList())
        // Success counts only after the SAS was computed locally, compared and shown (security.md 4.2 / I7). A
        // pair_result{ok} straight after the challenge would skip the human check entirely.
        if (phase !is PairingPhase.ShowingSas) {
            return fail(
                PairingFailure.PROTOCOL,
                listOf(PairingEffect.Send(unpair(now)), close("pair_result before sas")),
            )
        }
        val deviceId = payload.deviceId
        val token = payload.deviceToken
        val pc = payload.pc
        if (deviceId == null || token == null || pc == null || pc.pcId != qr.pcId) {
            return fail(PairingFailure.PROTOCOL, listOf(close("bad pair_result")))
        }
        val result = PairingResult(deviceId, token, pc, qr.pin, HostBookState.fromQr(qr))
        phase = PairingPhase.Completed(result)
        wipe()
        return listOf(PairingEffect.Completed(result))
    }

    private fun failureForError(code: String): PairingFailure = when (code) {
        "E_PAIR_REJECTED" -> PairingFailure.PAIR_REJECTED
        "E_PAIR_BUSY" -> PairingFailure.PAIR_BUSY
        "E_PAIR_FAILED" -> PairingFailure.PAIR_FAILED
        else -> PairingFailure.PROTOCOL
    }

    private fun fail(failure: PairingFailure, before: List<PairingEffect>): List<PairingEffect> {
        phase = PairingPhase.Failed(failure)
        wipe()
        return before + PairingEffect.Failed(failure)
    }

    private fun wipe() {
        qr.wipe()
        challenge?.fill(0)
    }

    private fun unpair(now: Instant): ClientMessage =
        UnpairMessage(FrameMeta(ids(), Ts.of(now)), UnpairPayload(pairingId = qr.pairingId))

    private fun close(reason: String) = PairingEffect.Close(CLOSE_NORMAL, reason)

    private companion object {
        const val CLOSE_NORMAL = 1000
    }
}
