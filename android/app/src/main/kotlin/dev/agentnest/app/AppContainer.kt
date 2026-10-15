package dev.agentnest.app

import android.app.Application
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import dev.agentnest.app.data.AppSettings
import dev.agentnest.app.data.NestRepository
import dev.agentnest.app.data.PairedInfo
import dev.agentnest.app.data.PairingData
import dev.agentnest.app.data.PairingStore
import dev.agentnest.app.data.SnapshotCache
import dev.agentnest.app.data.toInfo
import dev.agentnest.app.notify.AlertNotifier
import dev.agentnest.app.notify.ApprovalNotifier
import dev.agentnest.app.notify.LinkNotifier
import dev.agentnest.app.pairing.PairingController
import dev.agentnest.app.service.LinkService
import dev.agentnest.app.vault.DeviceKey
import dev.agentnest.app.vault.TokenVault
import dev.agentnest.core.crypto.B64
import dev.agentnest.core.link.DeviceDescriptor
import dev.agentnest.core.link.OkHttpWsTransport
import dev.agentnest.core.link.PairingResult
import dev.agentnest.core.protocol.SnapshotMessage
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant

/**
 * Hand-written dependency container (docs/android.md 1.3: no DI framework). One instance per process, created by
 * [AgentNestApp]. Everything that outlives an Activity lives here.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AppContainer(private val app: Application) {
    val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** One thread for every pairing/cache write, so their order is the order they were requested. */
    val storeDispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(1)

    val settings = AppSettings(app, scope)
    val pairingStore = PairingStore(app)
    val snapshotCache = SnapshotCache(app)
    val vault = TokenVault()
    val deviceKey = DeviceKey()
    val repository = NestRepository(scope)
    val approvalNotifier = ApprovalNotifier(app)
    val alertNotifier = AlertNotifier(app)
    val linkNotifier = LinkNotifier(app)

    /** Notification deep links waiting for the UI; each id is consumed once. */
    val approvalLinks = Channel<String>(Channel.BUFFERED)

    /** False until the stored pairing and snapshot cache were read (the UI shows an empty background until then). */
    val ready = MutableStateFlow(false)

    /** Non-secret summary of the stored pairing. */
    val paired: StateFlow<PairedInfo?> = pairingStore.data
        .map { it?.toInfo() }
        .stateIn(scope, SharingStarted.Eagerly, null)

    val pairingController = PairingController(
        scope = scope,
        transportFactory = { pin -> OkHttpWsTransport(pin) },
        devicePublicKey = { deviceKey.publicKeySpki() },
        device = { deviceDescriptor() },
        persist = { result -> persistPairing(result) },
        onPersisted = { onPairingPersisted() },
    )

    val controller: AndroidAppController by lazy { AndroidAppController(app, this) }

    init {
        scope.launch {
            val data = pairingStore.load()
            val cached = snapshotCache.load()
            repository.restore(cached?.first, cached?.second, paired = data != null)
            if (data != null && data.sealedToken == null) repository.markRevoked()
            ready.value = true
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Service
    // ---------------------------------------------------------------------------------------------

    /** Starts (or nudges) the foreground link service. Only call from a visible app, a notification action or boot. */
    fun startLinkService(action: String = LinkService.ACTION_START) {
        val intent = Intent(app, LinkService::class.java).setAction(action)
        try {
            ContextCompat.startForegroundService(app, intent)
        } catch (e: Exception) {
            // ForegroundServiceStartNotAllowedException (API 31+): tell the user instead of crashing.
            alertNotifier.serviceStartBlocked()
        }
    }

    /** The app became visible: start the service when a usable pairing exists. */
    fun onAppStarted() {
        repository.setAppVisible(true)
        scope.launch {
            val data = pairingStore.load()
            if (data?.sealedToken != null) startLinkService()
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Pairing lifecycle
    // ---------------------------------------------------------------------------------------------

    private fun deviceDescriptor(): DeviceDescriptor {
        val named = try {
            Settings.Global.getString(app.contentResolver, "device_name")
        } catch (e: Exception) {
            null
        }
        val name = named?.takeIf { it.isNotBlank() } ?: Build.MODEL
        return DeviceDescriptor(
            name = name,
            model = Build.MODEL,
            osVersion = "Android ${Build.VERSION.RELEASE}",
            appVersion = APP_VERSION,
        )
    }

    /** Seals the device token into the Keystore vault and stores the pairing. The plaintext token is wiped from the byte array. */
    private suspend fun persistPairing(result: PairingResult) {
        withContext(storeDispatcher) {
            val plain = result.deviceToken.toByteArray(Charsets.UTF_8)
            val sealed = try {
                vault.seal(plain)
            } finally {
                plain.fill(0)
            }
            pairingStore.save(
                PairingData(
                    deviceId = result.deviceId,
                    pcId = result.pc.pcId,
                    pcName = result.pc.name,
                    pinString = result.pin.toPinString(),
                    hosts = result.hosts,
                    sealedToken = B64.encode(sealed),
                ),
            )
            snapshotCache.clear()
            settings.setKeyResetNotice(false)
        }
    }

    private fun onPairingPersisted() {
        repository.restore(null, null, paired = true)
        startLinkService(LinkService.ACTION_RESTART)
    }

    /** Deletes every stored trace of the pairing: data, snapshot cache and both Keystore entries. */
    suspend fun wipePairingLocal() {
        pairingStore.wipeAll()
        snapshotCache.clear()
        vault.deleteKey()
        deviceKey.delete()
    }

    /** The Keystore refused the stored token (docs/android.md 4.1): wipe, remember to tell the user, show "unpaired". */
    suspend fun handleVaultInvalid() {
        withContext(storeDispatcher) { wipePairingLocal() }
        settings.setKeyResetNotice(true)
        repository.restore(null, null, paired = false)
    }

    /** Caches a snapshot for the next cold start. */
    fun saveSnapshot(message: SnapshotMessage) {
        scope.launch(storeDispatcher) { snapshotCache.save(message, Instant.now()) }
    }

    /** Queues a notification deep link for the UI. */
    fun emitApprovalLink(requestId: String) {
        approvalLinks.trySend(requestId)
    }

    companion object {
        /** Reported to the PC in `pair` and `hello`. */
        const val APP_VERSION = "0.1.0"
    }
}
