package dev.agentnest.app.data

import dev.agentnest.core.link.HostBookState

/**
 * What is persisted about the pairing (DataStore). The device token is stored only as the Keystore-sealed blob
 * ([sealedToken]); [pinString] is the public `sha256/...` SPKI pin of the PC.
 */
data class PairingData(
    val deviceId: String,
    val pcId: String,
    val pcName: String,
    val pinString: String,
    val hosts: HostBookState,
    /** Base64 of `[iv(12) | ciphertext+tag]`; null after the PC revoked the device. */
    val sealedToken: String?,
) {
    override fun toString(): String = "PairingData(deviceId=$deviceId, pcId=$pcId, pcName=$pcName, token=<redacted>)"
}

/** The non-secret summary the UI shows in settings. */
data class PairedInfo(
    val deviceId: String,
    val pcId: String,
    val pcName: String,
    val hosts: List<String>,
    val hasToken: Boolean,
)

/** Pure conversion of [HostBookState] lists to and from the single strings kept in DataStore. */
object HostBookCodec {
    private const val SEPARATOR = ","

    /** Host names and IP literals never contain a comma, so a comma-joined string round-trips. */
    fun encode(items: List<String>): String = items.joinToString(SEPARATOR)

    /** Inverse of [encode]; blank input gives an empty list. */
    fun decode(text: String?): List<String> {
        if (text.isNullOrBlank()) return emptyList()
        return text.split(SEPARATOR).map { it.trim() }.filter { it.isNotEmpty() }
    }
}

/** Builds the UI summary from the stored data. */
fun PairingData.toInfo(): PairedInfo = PairedInfo(
    deviceId = deviceId,
    pcId = pcId,
    pcName = pcName,
    hosts = hosts.candidates(),
    hasToken = sealedToken != null,
)
