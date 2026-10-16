package dev.agentnest.app.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dev.agentnest.core.protocol.Codec
import dev.agentnest.core.protocol.DecodeResult
import dev.agentnest.core.protocol.SnapshotMessage
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException
import java.time.Instant

private val Context.cacheDataStore: DataStore<Preferences> by preferencesDataStore(name = "snapshot_cache")

/**
 * The last `snapshot` for cold starts (docs/android.md 2.1: never an empty screen). Pending approval cards are NOT
 * stored (they expire within minutes and carry command text), and neither are the other command / path / prompt
 * fields: [SnapshotRedaction] keeps only what a first frame needs.
 */
class SnapshotCache(context: Context) {
    private val store: DataStore<Preferences> = context.applicationContext.cacheDataStore

    /** Saves [message] without its approval cards and without command / path / prompt text. */
    suspend fun save(message: SnapshotMessage, savedAt: Instant) {
        val text = Codec.encodeAny(SnapshotRedaction.strip(message))
        store.edit {
            it[SNAPSHOT] = text
            it[SAVED_AT] = savedAt.toEpochMilli()
        }
    }

    /** The cached snapshot and when it was saved, or null. */
    suspend fun load(): Pair<SnapshotMessage, Instant>? {
        val prefs = store.data.catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }.first()
        val text = prefs[SNAPSHOT] ?: return null
        val savedAt = prefs[SAVED_AT] ?: return null
        val decoded = Codec.decodeServer(text) as? DecodeResult.Decoded ?: return null
        val message = decoded.message as? SnapshotMessage ?: return null
        return message to Instant.ofEpochMilli(savedAt)
    }

    /** Deletes the cache (unpair / re-pair). */
    suspend fun clear() {
        store.edit { it.clear() }
    }

    private companion object {
        val SNAPSHOT = stringPreferencesKey("snapshot_json")
        val SAVED_AT = longPreferencesKey("saved_at_ms")
    }
}
