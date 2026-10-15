package dev.agentnest.app.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import java.io.IOException

private val Context.settingsDataStore: DataStore<Preferences> by preferencesDataStore(name = "settings")

/** User preferences in DataStore (docs/character.md 3.4). Defaults are the calm, safe ones. */
class AppSettings(context: Context, scope: CoroutineScope) {
    private val store: DataStore<Preferences> = context.applicationContext.settingsDataStore

    private val settingsFlow = store.data
        .catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }

    /** Current preferences (defaults until the first read finishes). */
    val state: StateFlow<SettingsState> = settingsFlow
        .map { it.toSettings() }
        .stateIn(scope, SharingStarted.Eagerly, SettingsState())

    /** True after the Keystore refused the stored token and the pairing was wiped (shown once on the home screen). */
    val keyResetNotice: StateFlow<Boolean> = settingsFlow
        .map { it[KEY_RESET_NOTICE] ?: false }
        .stateIn(scope, SharingStarted.Eagerly, false)

    /** Reads the stored preferences right now (used by the boot receiver, where [state] may not be loaded yet). */
    suspend fun current(): SettingsState = settingsFlow.first().toSettings()

    suspend fun setAnimationsEnabled(value: Boolean) {
        store.edit { it[KEY_ANIMATIONS] = value }
    }

    suspend fun setSoundEnabled(value: Boolean) {
        store.edit { it[KEY_SOUND] = value }
    }

    suspend fun setReducedMotion(value: Boolean) {
        store.edit { it[KEY_REDUCED] = value }
    }

    suspend fun setAutoStartOnBoot(value: Boolean) {
        store.edit { it[KEY_AUTO_START] = value }
    }

    suspend fun setKeyResetNotice(value: Boolean) {
        store.edit { it[KEY_RESET_NOTICE] = value }
    }

    private fun Preferences.toSettings(): SettingsState = SettingsState(
        animationsEnabled = this[KEY_ANIMATIONS] ?: true,
        soundEnabled = this[KEY_SOUND] ?: true,
        reducedMotion = this[KEY_REDUCED] ?: false,
        autoStartOnBoot = this[KEY_AUTO_START] ?: false,
    )

    private companion object {
        val KEY_ANIMATIONS = booleanPreferencesKey("animations_enabled")
        val KEY_SOUND = booleanPreferencesKey("sound_enabled")
        val KEY_REDUCED = booleanPreferencesKey("low_power_mode")
        val KEY_AUTO_START = booleanPreferencesKey("auto_start_on_boot")
        val KEY_RESET_NOTICE = booleanPreferencesKey("key_reset_notice")
    }
}
