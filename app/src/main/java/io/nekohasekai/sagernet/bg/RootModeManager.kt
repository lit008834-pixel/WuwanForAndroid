package io.nekohasekai.sagernet.bg

import android.content.Context
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.bg.ebpf.RuntimeMode

/**
 * Selects the Android service hosting the existing proxy core. AUTO also uses
 * this service, but only establishes a system VPN if root TUN setup fails.
 * No shell calls, blocking IO or DataStore mutation in service-class getters.
 */
object RootModeManager {
    fun resolveConfiguredMode(): String = when (DataStore.serviceMode) {
        Key.MODE_PROXY -> Key.MODE_PROXY
        else -> Key.MODE_VPN
    }

    fun prepare(@Suppress("UNUSED_PARAMETER") context: Context): String = resolveConfiguredMode()
}

object CaptureModeStatus {
    fun label(): String = when (RuntimeMode.active) {
        "ebpf" -> "eBPF transparent proxy"
        "vpn" -> "VPNService mode"
        else -> "Stopped"
    }
}
