package io.nekohasekai.sagernet.bg

import android.content.Context
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.Logs
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Chooses the safest available traffic-capture mode.
 *
 * Root alone is not enough for eBPF: the kernel must expose BPF filesystem and
 * BTF metadata and the device must provide a loader (bpftool or tc). If any
 * prerequisite is missing, the app deliberately falls back to Android VPN.
 */
object RootModeManager {
    enum class CaptureMode(val key: String) {
        VPN(Key.MODE_VPN),
        ROOT_EBPF(Key.MODE_PROXY)
    }

    data class Capability(
        val root: Boolean,
        val bpfFilesystem: Boolean,
        val btf: Boolean,
        val loader: String?,
    ) {
        val eBpfReady: Boolean get() = root && bpfFilesystem && btf && loader != null
    }

    @Volatile
    private var lastCapability: Capability? = null

    fun capability(): Capability = synchronized(this) {
        lastCapability ?: probe().also { lastCapability = it }
    }

    fun resolveConfiguredMode(): String {
        return when (DataStore.serviceMode) {
            Key.MODE_PROXY -> if (capability().eBpfReady) Key.MODE_PROXY else Key.MODE_VPN
            Key.MODE_VPN -> Key.MODE_VPN
            Key.MODE_AUTO -> if (capability().eBpfReady) Key.MODE_PROXY else Key.MODE_VPN
            else -> Key.MODE_VPN
        }
    }

    fun prepare(context: Context): String {
        val cap = capability()
        val selected = resolveConfiguredMode()
        if (selected == Key.MODE_PROXY) {
            Logs.i("Capture mode: eBPF transparent proxy; root=${cap.root}, bpf=${cap.bpfFilesystem}, btf=${cap.btf}, loader=${cap.loader}")
        } else {
            Logs.i("Capture mode: Android VpnService; eBPF prerequisites unavailable (root=${cap.root}, bpf=${cap.bpfFilesystem}, btf=${cap.btf}, loader=${cap.loader})")
        }
        return selected
    }

    private fun probe(): Capability {
        val root = runRoot("id").first.trim().startsWith("uid=0")
        if (!root) return Capability(false, false, false, null)
        val bpf = runRoot("test -d /sys/fs/bpf").second == 0
        val btf = runRoot("test -r /sys/kernel/btf/vmlinux").second == 0
        val loader = listOf("bpftool", "tc").firstOrNull { runRoot("command -v $it").second == 0 }
        return Capability(root, bpf, btf, loader)
    }

    private fun runRoot(command: String): Pair<String, Int> {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
            val output = BufferedReader(InputStreamReader(process.inputStream)).use { it.readText() }
            val error = BufferedReader(InputStreamReader(process.errorStream)).use { it.readText() }
            val code = process.waitFor()
            if (code != 0 && error.isNotBlank()) Logs.d("Root probe failed: $command: ${error.trim()}")
            output to code
        } catch (e: Exception) {
            Logs.d("Root probe unavailable: ${e.message}")
            "" to -1
        }
    }
}

object CaptureModeStatus {
    fun label(): String = when (RootModeManager.resolveConfiguredMode()) {
        Key.MODE_PROXY -> "eBPF transparent proxy"
        else -> "VpnService mode"
    }
}
