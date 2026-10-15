package dev.agentnest.app.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.DateRange
import androidx.compose.material.icons.filled.Face
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import dev.agentnest.app.character.MotionPolicy
import dev.agentnest.app.nav.NavState
import dev.agentnest.app.nav.Screen
import dev.agentnest.app.ui.agents.AgentsScreen
import dev.agentnest.app.ui.agents.SessionDetailScreen
import dev.agentnest.app.ui.activity.ActivityScreen
import dev.agentnest.app.ui.approvals.ApprovalDetailScreen
import dev.agentnest.app.ui.approvals.ApprovalHistoryScreen
import dev.agentnest.app.ui.approvals.ApprovalsScreen
import dev.agentnest.app.ui.common.LinkBannerActions
import dev.agentnest.app.ui.home.HomeActions
import dev.agentnest.app.ui.home.HomeInputs
import dev.agentnest.app.ui.home.HomeScreen
import dev.agentnest.app.ui.projects.ProjectsScreen
import dev.agentnest.app.ui.settings.DevicesScreen
import dev.agentnest.app.ui.settings.DiagnosticsScreen
import dev.agentnest.app.ui.settings.PairingScreen
import dev.agentnest.app.ui.settings.SettingsActions
import dev.agentnest.app.ui.settings.SettingsScreen
import dev.agentnest.app.ui.theme.AgentNestTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.time.Instant

private class TabItem(val screen: Screen, val label: String, val icon: ImageVector)

private val TABS: List<TabItem> = listOf(
    TabItem(Screen.Home, S.TAB_HOME, Icons.Filled.Home),
    TabItem(Screen.Agents, S.TAB_AGENTS, Icons.Filled.Face),
    TabItem(Screen.Projects, S.TAB_PROJECTS, Icons.Filled.Build),
    TabItem(Screen.Activity, S.TAB_ACTIVITY, Icons.Filled.DateRange),
    TabItem(Screen.Settings, S.TAB_SETTINGS, Icons.Filled.Settings),
)

/** A clock that ticks once a second while the app is visible (countdowns, "3분 전"). */
@Composable
fun rememberNow(active: Boolean): State<Instant> {
    val state = remember { mutableStateOf(Instant.now()) }
    LaunchedEffect(active) {
        if (active) {
            while (true) {
                state.value = Instant.now()
                delay(1000)
            }
        }
    }
    return state
}

/** Root of the Compose UI: theme, bottom tabs, manual navigation (sealed [Screen] + BackHandler). */
@Composable
fun AgentNestRoot(controller: AppController) {
    AgentNestTheme {
        val nav = rememberSaveable(saver = NavState.Saver) { NavState() }
        val nest by controller.nest.collectAsState()
        val settings by controller.settings.collectAsState()
        val paired by controller.paired.collectAsState()
        val pairing by controller.pairing.collectAsState()
        val paused by controller.paused.collectAsState()
        val visible by controller.appVisible.collectAsState()
        val keyReset by controller.keyResetNotice.collectAsState()
        val ready by controller.ready.collectAsState()
        val nowState = rememberNow(visible)
        val now = nowState.value
        val scope = rememberCoroutineScope()
        val snackbar = remember { SnackbarHostState() }

        BackHandler(enabled = nav.canGoBack) { nav.pop() }
        if (!ready) {
            // The stored pairing is still being read (tens of milliseconds): an empty background avoids a flash of the wrong screen.
            Box(modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background))
            return@AgentNestTheme
        }
        LaunchedEffect(Unit) {
            controller.approvalLinks.collect { id -> nav.push(Screen.ApprovalDetail(id)) }
        }

        val motion = remember(visible, settings.animationsEnabled, settings.reducedMotion) {
            MotionPolicy.resolve(settings.animationsEnabled, settings.reducedMotion, controller.systemMotion())
        }

        val linkActions = LinkBannerActions(
            onReconnect = controller::reconnect,
            onRepair = {
                controller.repair()
                nav.resetTo(Screen.Home)
                nav.push(Screen.Pairing)
            },
            onManualHost = controller::addManualHost,
            onRescanQr = { scope.launch { snackbar.showSnackbar(controller.rescanAddresses()) } },
        )

        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            snackbarHost = { SnackbarHost(snackbar) },
            bottomBar = {
                if (nav.current.isTab) {
                    NavigationBar {
                        for (tab in TABS) {
                            NavigationBarItem(
                                selected = nav.activeTab == tab.screen,
                                onClick = { nav.selectTab(tab.screen) },
                                icon = { Icon(tab.icon, contentDescription = null) },
                                label = { Text(tab.label) },
                            )
                        }
                    }
                }
            },
        ) { padding ->
            Box(modifier = Modifier.padding(padding)) {
                when (val screen = nav.current) {
                    Screen.Home -> HomeScreen(
                        nest = nest,
                        now = now,
                        inputs = HomeInputs(paired, paused, keyReset, motion, visible),
                        controller = controller,
                        actions = HomeActions(
                            link = linkActions,
                            onOpenApproval = { nav.push(Screen.ApprovalDetail(it)) },
                            onOpenApprovals = { nav.push(Screen.Approvals) },
                            onOpenHistory = { nav.push(Screen.ApprovalHistory) },
                            onOpenSession = { nav.push(Screen.SessionDetail(it)) },
                            onStartPairing = { nav.push(Screen.Pairing) },
                        ),
                    )
                    Screen.Agents -> AgentsScreen(nest, now, onOpenSession = { nav.push(Screen.SessionDetail(it)) })
                    Screen.Projects -> ProjectsScreen(nest, now)
                    Screen.Activity -> ActivityScreen(nest, controller)
                    Screen.Settings -> SettingsScreen(
                        nest = nest,
                        now = now,
                        settings = settings,
                        paired = paired,
                        controller = controller,
                        actions = SettingsActions(
                            onOpenDevices = { nav.push(Screen.Devices) },
                            onOpenDiagnostics = { nav.push(Screen.Diagnostics) },
                            onStartPairing = { nav.push(Screen.Pairing) },
                        ),
                    )
                    Screen.Approvals -> ApprovalsScreen(
                        nest = nest,
                        now = now,
                        onOpenApproval = { nav.push(Screen.ApprovalDetail(it)) },
                        onOpenHistory = { nav.push(Screen.ApprovalHistory) },
                        onBack = { nav.pop() },
                    )
                    Screen.ApprovalHistory -> ApprovalHistoryScreen(nest, onBack = { nav.pop() })
                    Screen.Pairing -> PairingScreen(
                        state = pairing,
                        controller = controller,
                        onBack = { nav.pop() },
                        onDone = { nav.resetTo(Screen.Home) },
                    )
                    Screen.Devices -> DevicesScreen(
                        paired = paired,
                        controller = controller,
                        onBack = { nav.pop() },
                        onUnpaired = { nav.resetTo(Screen.Home) },
                        onRepaired = {
                            nav.resetTo(Screen.Home)
                            nav.push(Screen.Pairing)
                        },
                    )
                    Screen.Diagnostics -> DiagnosticsScreen(nest, paired, now, onBack = { nav.pop() })
                    is Screen.SessionDetail -> SessionDetailScreen(screen.sessionKey, nest, now, controller, onBack = { nav.pop() })
                    is Screen.ApprovalDetail -> ApprovalDetailScreen(screen.requestId, nest, now, controller, onBack = { nav.pop() })
                }
            }
        }
    }
}
