package dev.agentnest.app.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dev.agentnest.core.link.HostBookState
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException

private val Context.pairingDataStore: DataStore<Preferences> by preferencesDataStore(name = "pairing")

/**
 * Persists the pairing (docs/android.md 1.3 `PairingStore`): device id, PC id/name, the public SPKI pin, the address
 * book and the Keystore-sealed device token. Never contains a plaintext token.
 */
class PairingStore(context: Context) {
    private val store: DataStore<Preferences> = context.applicationContext.pairingDataStore

    /** The stored pairing, or null while unpaired. */
    val data: Flow<PairingData?> = store.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }
        .map { it.toPairingData() }

    /** Reads the stored pairing once. */
    suspend fun load(): PairingData? = data.first()

    /** Stores a new pairing, replacing any old one. */
    suspend fun save(value: PairingData) {
        store.edit { p ->
            p.clear()
            p[DEVICE_ID] = value.deviceId
            p[PC_ID] = value.pcId
            p[PC_NAME] = value.pcName
            p[PIN] = value.pinString
            value.sealedToken?.let { p[SEALED_TOKEN] = it }
            writeHosts(p, value.hosts)
        }
    }

    /** Stores the address book; ignored while no pairing exists (so a wipe is never undone by a late write). */
    suspend fun saveHosts(hosts: HostBookState) {
        store.edit { p ->
            if (p[DEVICE_ID] != null) writeHosts(p, hosts)
        }
    }

    /** Removes only the device token (the PC revoked this device); the PC identity stays for the "re-pair" screen. */
    suspend fun wipeToken() {
        store.edit { it.remove(SEALED_TOKEN) }
    }

    /** Removes everything. */
    suspend fun wipeAll() {
        store.edit { it.clear() }
    }

    private fun writeHosts(p: androidx.datastore.preferences.core.MutablePreferences, hosts: HostBookState) {
        p[PORT] = hosts.port
        p[HOSTS_WELCOME] = HostBookCodec.encode(hosts.welcome)
        p[HOSTS_MANUAL] = HostBookCodec.encode(hosts.manual)
        p[HOSTS_QR] = HostBookCodec.encode(hosts.qr)
        val last = hosts.lastSuccess
        if (last != null) p[LAST_SUCCESS] = last else p.remove(LAST_SUCCESS)
    }

    private fun Preferences.toPairingData(): PairingData? {
        val deviceId = this[DEVICE_ID] ?: return null
        val pcId = this[PC_ID] ?: return null
        val pin = this[PIN] ?: return null
        val hosts = HostBookState(
            port = this[PORT] ?: HostBookState.DEFAULT_PORT,
            welcome = HostBookCodec.decode(this[HOSTS_WELCOME]),
            manual = HostBookCodec.decode(this[HOSTS_MANUAL]),
            qr = HostBookCodec.decode(this[HOSTS_QR]),
            lastSuccess = this[LAST_SUCCESS],
        )
        return PairingData(deviceId, pcId, this[PC_NAME] ?: "", pin, hosts, this[SEALED_TOKEN])
    }

    private companion object {
        val DEVICE_ID = stringPreferencesKey("device_id")
        val PC_ID = stringPreferencesKey("pc_id")
        val PC_NAME = stringPreferencesKey("pc_name")
        val PIN = stringPreferencesKey("spki_pin")
        val SEALED_TOKEN = stringPreferencesKey("token_sealed")
        val PORT = intPreferencesKey("port")
        val HOSTS_WELCOME = stringPreferencesKey("hosts_welcome")
        val HOSTS_MANUAL = stringPreferencesKey("hosts_manual")
        val HOSTS_QR = stringPreferencesKey("hosts_qr")
        val LAST_SUCCESS = stringPreferencesKey("hosts_last_success")
    }
}
