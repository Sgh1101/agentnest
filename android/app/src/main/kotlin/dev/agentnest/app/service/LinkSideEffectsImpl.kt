package dev.agentnest.app.service

import dev.agentnest.app.AppContainer
import dev.agentnest.core.link.HostBookState
import dev.agentnest.core.link.LinkSideEffects
import dev.agentnest.core.link.SecurityAlertKind
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * The persistence and notification hooks of `LinkClient`. Storage writes run on the container's single-threaded
 * store dispatcher so their order is the order of the effects (a late `persistHosts` can never undo a wipe).
 * [onCredentialsGone] clears the in-memory credentials of the running service at once; [onPairingWiped] lets the
 * service stop itself after the pairing was erased.
 */
class LinkSideEffectsImpl(
    private val container: AppContainer,
    private val scope: CoroutineScope,
    private val onCredentialsGone: () -> Unit,
    private val onPairingWiped: () -> Unit,
) : LinkSideEffects {

    override fun persistHosts(hosts: HostBookState) {
        scope.launch(container.storeDispatcher) { container.pairingStore.saveHosts(hosts) }
    }

    override fun wipeDeviceToken() {
        onCredentialsGone()
        scope.launch(container.storeDispatcher) {
            container.pairingStore.wipeToken()
            container.vault.deleteKey()
        }
    }

    override fun wipePairing() {
        onCredentialsGone()
        scope.launch(container.storeDispatcher) {
            container.wipePairingLocal()
            onPairingWiped()
        }
    }

    override fun securityAlert(kind: SecurityAlertKind) {
        container.alertNotifier.security(kind)
    }
}
