package dev.agentnest.app.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dev.agentnest.core.nest.ApprovalHistory
import dev.agentnest.core.nest.ApprovalHistoryEntry
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import java.io.IOException

private val Context.historyDataStore: DataStore<Preferences> by preferencesDataStore(name = "approval_history")

/** The last 50 resolved approvals on the phone (docs/android.md 1.3 `ApprovalHistoryStore`). No command text is stored. */
class ApprovalHistoryStore(context: Context) {
    private val store: DataStore<Preferences> = context.applicationContext.historyDataStore

    /** Saves [history]. */
    suspend fun save(history: ApprovalHistory) {
        val text = ApprovalHistoryCodec.encode(history)
        store.edit { it[HISTORY] = text }
    }

    /** The stored entries, newest first. */
    suspend fun load(): List<ApprovalHistoryEntry> {
        val prefs = store.data.catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }.first()
        return ApprovalHistoryCodec.decode(prefs[HISTORY])
    }

    /** Deletes the history (unpair / re-pair). */
    suspend fun clear() {
        store.edit { it.clear() }
    }

    private companion object {
        val HISTORY = stringPreferencesKey("history_json")
    }
}
