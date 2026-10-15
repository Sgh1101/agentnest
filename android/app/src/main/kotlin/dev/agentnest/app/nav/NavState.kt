package dev.agentnest.app.nav

import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.saveable.listSaver

/**
 * The back stack. The first entry is always a tab root. Selecting a tab replaces the stack with `[Home, tab]`
 * (or `[Home]`), so Back from any tab leads to Home first.
 */
class NavState(initial: List<Screen> = listOf(Screen.Home)) {
    private val entries = mutableStateListOf<Screen>().apply {
        addAll(initial.ifEmpty { listOf(Screen.Home) })
    }

    /** The visible destination. */
    val current: Screen get() = entries.last()

    /** True when Back would pop something (the stack is deeper than one entry). */
    val canGoBack: Boolean get() = entries.size > 1

    /** The stack for the saver (bottom first). */
    val stack: List<Screen> get() = entries.toList()

    /** Opens [screen] on top of the current one. */
    fun push(screen: Screen) {
        if (current == screen) return
        entries.add(screen)
    }

    /** Pops one entry; no-op at the root. */
    fun pop() {
        if (entries.size > 1) entries.removeAt(entries.lastIndex)
    }

    /** Switches to a bottom-bar tab. */
    fun selectTab(tab: Screen) {
        entries.clear()
        entries.add(Screen.Home)
        if (tab != Screen.Home) entries.add(tab)
    }

    /** Replaces the whole stack (used after pairing finishes). */
    fun resetTo(screen: Screen) {
        entries.clear()
        entries.add(Screen.Home)
        if (screen != Screen.Home) entries.add(screen)
    }

    /** The tab the current destination belongs to (detail screens inherit the tab below them). */
    val activeTab: Screen
        get() = entries.lastOrNull { it.isTab } ?: Screen.Home

    companion object {
        /** Saver for `rememberSaveable`. */
        val Saver = listSaver<NavState, String>(
            save = { state -> state.stack.map { it.encode() } },
            restore = { saved -> NavState(saved.mapNotNull { Screen.decode(it) }) },
        )
    }
}
