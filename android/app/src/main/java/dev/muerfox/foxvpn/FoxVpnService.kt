package dev.muerfox.foxvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.net.InetAddress

class FoxVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val config = intent?.getStringExtra(EXTRA_CONFIG).orEmpty()
        val host = intent?.getStringExtra(EXTRA_HOST).orEmpty()
        val ipv6 = intent?.getBooleanExtra(EXTRA_IPV6, false) ?: false
        val dns = intent?.getStringArrayExtra(EXTRA_DNS) ?: arrayOf("1.1.1.1", "8.8.8.8")
        val mtu = intent?.getIntExtra(EXTRA_MTU, 1280) ?: 1280
        val full = intent?.getBooleanExtra(EXTRA_FULL, true) ?: true
        val split = intent?.getStringArrayExtra(EXTRA_SPLIT) ?: emptyArray()
        startInForeground()
        NativeBridge.service = this
        Thread({
            val established = establish(host, ipv6, dns, mtu, full, split)
            if (established == null) {
                NativeBridge.onEvent("{\"type\":\"error\",\"message\":\"Android did not grant a VPN interface\",\"hint\":\"Approve the VPN consent dialog and try again.\"}")
                stopSelf()
                return@Thread
            }
            val error = NativeBridge.startOwned(established, config)
            if (error.isNotEmpty()) {
                NativeBridge.onEvent("{\"type\":\"error\",\"message\":${org.json.JSONObject.quote(error)},\"hint\":\"The tunnel stopped.\"}")
            }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }, "fox-vpn").start()
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        NativeBridge.stop()
        NativeBridge.service = null
        super.onDestroy()
    }

    override fun onRevoke() {
        NativeBridge.stop()
        stopSelf()
        super.onRevoke()
    }

    private fun establish(host: String, ipv6: Boolean, dns: Array<String>, mtu: Int, full: Boolean, split: Array<String>): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("Fox-VPN")
            .addAddress("10.77.0.2", 24)
            .setMtu(mtu.coerceIn(1280, 1500))
            .setBlocking(false)
        if (full) {
            builder.addRoute("0.0.0.0", 0)
        } else {
            for (cidr in split) {
                val parts = cidr.split("/")
                if (parts.size == 2) {
                    val prefix = parts[1].toIntOrNull() ?: continue
                    if (prefix in 0..32) builder.addRoute(parts[0], prefix)
                }
            }
        }
        if (!ipv6) {
            builder.addRoute("::", 0)
        }
        for (server in dns) {
            try {
                builder.addDnsServer(server)
            } catch (_: Exception) {
            }
        }
        if (Build.VERSION.SDK_INT >= 33) {
            try {
                val address = InetAddress.getByName(host)
                if (address.address.size == 4) {
                    builder.excludeRoute(IpPrefix(address, 32))
                }
            } catch (_: Exception) {
            }
        }
        return builder.establish()
    }

    private fun startInForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(CHANNEL, "Fox-VPN", NotificationManager.IMPORTANCE_LOW)
            manager.createNotificationChannel(channel)
        }
        val notification = Notification.Builder(this, CHANNEL)
            .setContentTitle("Fox-VPN")
            .setContentText("SSH tunnel is running")
            .setSmallIcon(R.drawable.ic_stat_fox)
            .build()
        startForeground(1, notification)
    }

    companion object {
        const val EXTRA_CONFIG = "config"
        const val EXTRA_HOST = "host"
        const val EXTRA_IPV6 = "ipv6"
        const val EXTRA_DNS = "dns"
        const val EXTRA_MTU = "mtu"
        const val EXTRA_FULL = "full"
        const val EXTRA_SPLIT = "split"
        private const val CHANNEL = "fox-vpn"
    }
}
