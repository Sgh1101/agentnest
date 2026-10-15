package dev.agentnest.app

import android.app.Application
import dev.agentnest.app.notify.Channels

/** Application: creates the notification channels and the process-wide [AppContainer]. */
class AgentNestApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        Channels.create(this)
        container = AppContainer(this)
    }
}
