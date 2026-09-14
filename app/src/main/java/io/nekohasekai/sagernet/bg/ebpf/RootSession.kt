package io.nekohasekai.sagernet.bg.ebpf

import android.content.Context
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import io.nekohasekai.sagernet.ktx.Logs
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/** A bounded su invocation. User-controlled node/config text never enters a shell. */
internal class RootProcess(context: Context, arguments: List<String>) : Closeable {
    private val output = StringBuilder()
    private val process: java.lang.Process
    init {
        check(android.os.Build.VERSION.SDK_INT >= 26) { "Root helper requires Android 8+" }
        val executable = File(context.applicationInfo.nativeLibraryDir, "libwuwan_ebpf.so")
        check(executable.isFile) { "eBPF helper missing for this ABI" }
        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        val command = (listOf(executable.absolutePath) + arguments).joinToString(" ", transform = ::quote)
        process = ProcessBuilder("su", "-c", "exec $command").redirectErrorStream(true).start()
        thread(name = "wuwan-root-log", isDaemon = true) {
            runCatching {
                process.inputStream.bufferedReader().use { reader ->
                    val buffer = CharArray(512)
                    while (true) {
                        val size = reader.read(buffer)
                        if (size < 0) break
                        synchronized(output) {
                            if (output.length < 16384) output.append(buffer, 0, minOf(size, 16384 - output.length))
                        }
                    }
                }
            }
        }
    }
    fun finished(): Boolean = try { process.exitValue(); true } catch (_: IllegalThreadStateException) { false }
    fun diagnostics(): String = synchronized(output) { output.toString().takeLast(4096) }
    fun await(timeoutMs: Long): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (!finished() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(50)
        return finished() && process.exitValue() == 0
    }
    override fun close() {
        process.destroy()
        runCatching { process.outputStream.close() }
    }
}

object RootProbe {
    /** Called on an IO worker at app launch; never equates su presence with grant. */
    fun inspect(context: Context): Boolean = try {
        RootProcess(context, listOf("probe")).use { process ->
            val ready = process.await(15000)
            Logs.i("RootProbe ready=$ready ${process.diagnostics()}")
            ready
        }
    } catch (error: Exception) {
        Logs.i("RootProbe VPN fallback: ${error.message}")
        false
    }
}

/** Owns the control connection and the received TUN; core never owns these FDs. */
class RootSession private constructor(
    private val process: RootProcess,
    private val socket: LocalSocket,
    val tun: ParcelFileDescriptor,
) : Closeable {
    private val closed = AtomicBoolean()

    fun activate(onFailure: (Exception) -> Unit) {
        socket.outputStream.write('A'.code)
        check(socket.inputStream.read() == 'K'.code) { "eBPF attach failed: ${process.diagnostics()}" }
        thread(name = "wuwan-ebpf-watch", isDaemon = true) {
            try {
                while (!closed.get()) {
                    Thread.sleep(2000)
                    if (closed.get()) break
                    socket.outputStream.write('H'.code)
                    check(socket.inputStream.read() == 'K'.code) { "eBPF helper stopped" }
                }
            } catch (error: Exception) {
                if (!closed.get()) onFailure(error)
            }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        // Shutdown wakes the helper, which closes all link FDs before TUN/socket.
        runCatching { socket.shutdownOutput() }
        runCatching { socket.close() }
        try {
            process.await(3000)
        } finally {
            process.close()
            tun.close()
        }
    }

    companion object {
        fun open(context: Context, mtu: Int): RootSession {
            val name = "wuwan-ebpf-${UUID.randomUUID()}"
            val process = RootProcess(context, listOf("serve", name, Process.myUid().toString(), mtu.toString()))
            var socket: LocalSocket? = null
            try {
                val deadline = SystemClock.elapsedRealtime() + 15000
                while (socket == null && SystemClock.elapsedRealtime() < deadline && !process.finished()) {
                    val attempt = LocalSocket()
                    try {
                        attempt.connect(LocalSocketAddress(name, LocalSocketAddress.Namespace.ABSTRACT))
                        socket = attempt
                    } catch (_: IOException) {
                        attempt.close()
                        Thread.sleep(100)
                    }
                }
                val connected = socket ?: error("Root/eBPF unavailable: ${process.diagnostics()}")
                connected.soTimeout = 5000
                check(connected.peerCredentials.uid == 0) { "Root helper peer is not UID 0" }
                check(connected.inputStream.read() == 'T'.code) { "Root helper did not send a TUN" }
                val descriptors = connected.ancillaryFileDescriptors ?: error("TUN fd missing")
                try {
                    check(descriptors.size == 1) { "Unexpected TUN descriptor count" }
                    return RootSession(process, connected, ParcelFileDescriptor.dup(descriptors.single()))
                } finally {
                    descriptors.forEach { android.system.Os.close(it) }
                }
            } catch (error: Exception) {
                runCatching { socket?.close() }
                process.close()
                throw error
            }
        }
    }
}

/** Propagated to BaseService so it completes cleanup before one VPN restart. */
class EbpfRestartException(cause: Exception) : Exception("eBPF failed; restarting in VPNService mode", cause)

object RuntimeMode {
    @Volatile var active: String = "stopped"
}
