package dev.muerfox.foxvpn

import android.os.ParcelFileDescriptor

/**
 * JNI boundary for libfox_vpn.so. Methods are called by the native tunnel
 * from worker threads, so view updates must hop to the main looper.
 */
object NativeBridge {
    init {
        System.loadLibrary("fox_vpn")
    }

    @JvmStatic
    var service: FoxVpnService? = null

    @JvmStatic
    var events: ((String) -> Unit)? = null

    @JvmStatic
    fun protectSocket(fd: Int): Boolean {
        val vpn = service ?: return false
        return try {
            vpn.protect(fd)
        } catch (_: Exception) {
            false
        }
    }

    @JvmStatic
    fun onEvent(json: String) {
        events?.invoke(json)
    }

    external fun start(tunFd: Int, configJson: String): String
    external fun stop()
    external fun decide(choice: Int)

    fun startOwned(tun: ParcelFileDescriptor, configJson: String): String {
        val fd = tun.detachFd()
        return start(fd, configJson)
    }
}
