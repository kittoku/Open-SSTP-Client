package kittoku.osc.l2tp

import android.app.PendingIntent
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunInterface
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunParameters
import com.arcansecurity.vpn.l2tpipsec.core.tunnel.TunProvider
import com.arcansecurity.vpn.l2tpipsec.core.util.Log
import com.arcansecurity.vpn.l2tpipsec.core.util.VpnLogger
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Creates the system TUN once PPP has handed us an address. Same idea as the library's own
 * provider, plus what Banafsh's other tunnels already do: the routes (everything, or everything except
 * the ranges the user asked to reach directly) and the apps that bypass the VPN.
 *
 * IPv6 is blackholed (a route without an address) so a dual-stack connection cannot leak around an IPv4-only tunnel.
 */
internal class L2tpTunProvider(
    private val service: VpnService,
    /** "a.b.c.d/len" entries; empty means everything. */
    private val routes: List<String>,
    /** Android 13 and newer: route everything except these "a.b.c.d/len" ranges. */
    private val excludedRoutes: List<String>,
    private val excludedApps: List<String>,
    private val onEstablished: (ParcelFileDescriptor) -> Unit,
    private val configureIntent: PendingIntent?,
    private val logger: VpnLogger,
) : TunProvider {

    private val log = Log(TAG, logger)

    override fun establish(params: TunParameters): TunInterface? {
        val builder = service.Builder()
            .setSession("Banafsh")
            .setMtu(params.mtu)
            .addAddress(params.address, params.prefixLength)

        var added = 0
        for (entry in routes) {
            val address = entry.substringBefore('/')
            val length = entry.substringAfter('/', "").toIntOrNull() ?: continue

            runCatching { builder.addRoute(address, length) }
                .onSuccess { added++ }
                .onFailure { log.w("Rejecting the route $entry", it) }
        }

        var excludedRouteCount = 0
        if (added == 0 && excludedRoutes.isNotEmpty() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // The cheap way to keep a long list of ranges out of the VPN (the system keeps one default route).
            builder.addRoute("0.0.0.0", 0)
            added = 1

            for (entry in excludedRoutes) {
                val length = entry.substringAfter('/', "").toIntOrNull() ?: continue

                runCatching { builder.excludeRoute(IpPrefix(InetAddress.getByName(entry.substringBefore('/')), length)) }
                    .onSuccess { excludedRouteCount++ }
            }
        }

        if (added == 0) {
            builder.addRoute("0.0.0.0", 0)
        }

        params.dnsServers.forEach { dns ->
            runCatching { builder.addDnsServer(dns) }
                .onFailure { log.w("Rejecting unusable DNS server '$dns'", it) }
        }
        params.searchDomain?.takeIf { it.isNotBlank() }?.let { domain ->
            runCatching { builder.addSearchDomain(domain) }
                .onFailure { log.w("Rejecting unusable search domain '$domain'", it) }
        }

        if (params.blockIpv6) {
            runCatching { builder.addRoute("::", 0) }
                .onFailure { log.w("Could not install the IPv6 blackhole route", it) }
        }

        var excluded = 0
        for (packageName in excludedApps) {
            // A package that is not installed throws: that is normal for a long list.
            if (runCatching { builder.addDisallowedApplication(packageName) }.isSuccess) excluded++
        }

        builder.setBlocking(true)
        configureIntent?.let { builder.setConfigureIntent(it) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
            builder.setUnderlyingNetworks(null)
        }

        val descriptor = builder.establish()
        if (descriptor == null) {
            log.w("VpnService.Builder.establish() returned null: consent was revoked")
            return null
        }

        log.i(
            "TUN up: ${params.address}/${params.prefixLength} mtu=${params.mtu} " +
                "dns=${params.dnsServers.joinToString(",").ifEmpty { "(none)" }} " +
                "routes=${if (added == 0) 1 else added} excludedRoutes=$excludedRouteCount bypassApps=$excluded " +
                "ipv6=${if (params.blockIpv6) "blocked" else "untouched"}",
        )
        onEstablished(descriptor)
        return ParcelFileDescriptorTun(descriptor)
    }

    private companion object {
        const val TAG = "Tun"
    }
}

/** [TunInterface] over the descriptor `VpnService.Builder.establish()` produced. */
private class ParcelFileDescriptorTun(
    private val descriptor: ParcelFileDescriptor,
) : TunInterface {

    private val input = FileInputStream(descriptor.fileDescriptor)
    private val output = FileOutputStream(descriptor.fileDescriptor)
    private val closed = AtomicBoolean(false)

    override fun readPacket(buffer: ByteArray): Int {
        if (closed.get()) return -1
        return try {
            input.read(buffer)
        } catch (e: IOException) {
            // Closing the descriptor from another thread is how a blocking read is cancelled.
            if (closed.get()) -1 else throw e
        }
    }

    override fun writePacket(buffer: ByteArray, offset: Int, length: Int) {
        if (closed.get()) return
        output.write(buffer, offset, length)
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { input.close() }
        runCatching { output.close() }
        runCatching { descriptor.close() }
    }
}
