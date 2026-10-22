package dev.muerfox.foxvpn

import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject
import java.io.File
import java.util.UUID

class MainActivity : AppCompatActivity() {
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var username: EditText
    private lateinit var password: EditText
    private lateinit var keyPath: EditText
    private lateinit var status: TextView
    private lateinit var logs: TextView
    private lateinit var fullTunnel: CheckBox
    private lateinit var tunnelDns: CheckBox
    private lateinit var remember: CheckBox
    private lateinit var connectButton: Button
    private var running = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        host = findViewById(R.id.host)
        port = findViewById(R.id.port)
        username = findViewById(R.id.username)
        password = findViewById(R.id.password)
        keyPath = findViewById(R.id.key_path)
        status = findViewById(R.id.status)
        logs = findViewById(R.id.logs)
        fullTunnel = findViewById(R.id.full_tunnel)
        tunnelDns = findViewById(R.id.tunnel_dns)
        remember = findViewById(R.id.remember)
        connectButton = findViewById(R.id.connect)
        port.setText("2222")
        username.setText("root")
        fullTunnel.isChecked = true
        tunnelDns.isChecked = true
        remember.isChecked = true
        loadRememberedPassword()

        connectButton.setOnClickListener {
            if (running) {
                NativeBridge.stop()
                stopService(Intent(this, FoxVpnService::class.java))
                running = false
                setStatus("Disconnected")
            } else {
                val prepare = VpnService.prepare(this)
                if (prepare != null) {
                    startActivityForResult(prepare, REQUEST_VPN)
                } else {
                    connect()
                }
            }
        }
        NativeBridge.events = { json ->
            runOnUiThread { onNativeEvent(json) }
        }
        setStatus("Disconnected")
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) connect() else setStatus("Error: VPN permission was denied. No traffic was captured.")
        }
    }

    private fun connect() {
        val config = buildConfig()
        val intent = Intent(this, FoxVpnService::class.java)
            .putExtra(FoxVpnService.EXTRA_CONFIG, config.toString())
            .putExtra(FoxVpnService.EXTRA_HOST, host.text.toString().trim())
            .putExtra(FoxVpnService.EXTRA_IPV6, false)
            .putExtra(FoxVpnService.EXTRA_DNS, arrayOf("1.1.1.1", "8.8.8.8"))
            .putExtra(FoxVpnService.EXTRA_MTU, 1280)
            .putExtra(FoxVpnService.EXTRA_FULL, fullTunnel.isChecked)
            .putExtra(FoxVpnService.EXTRA_SPLIT, emptyArray<String>())
        startForegroundService(intent)
        running = true
        setStatus("Connecting")
    }

    private fun buildConfig(): JSONObject {
        val passwordText = password.text.toString()
        if (remember.isChecked && passwordText.isNotEmpty()) {
            prefs().edit().putString("password", passwordText).apply()
        }
        val auth = if (keyPath.text.toString().isBlank()) "password" else "private_key"
        val known = File(filesDir, "known_hosts").absolutePath
        return JSONObject()
            .put("id", "android")
            .put("name", "Android")
            .put("host", host.text.toString().trim())
            .put("port", port.text.toString().toIntOrNull() ?: 2222)
            .put("username", username.text.toString().ifBlank { "root" })
            .put("authentication", auth)
            .put("key_path", keyPath.text.toString().trim())
            .put("routing_mode", if (fullTunnel.isChecked) "full_tunnel" else "split_tunnel")
            .put("auto_networks", false)
            .put("tunnel_dns", tunnelDns.isChecked)
            .put("dns_servers", org.json.JSONArray(listOf("1.1.1.1", "8.8.8.8")))
            .put("ipv4", true)
            .put("ipv6", false)
            .put("reconnect", true)
            .put("verbose_logging", true)
            .put("connect_timeout_secs", 20)
            .put("keepalive_secs", 15)
            .put("kill_switch", false)
            .put("exclude_lan", false)
            .put("transport", "ssh_direct")
            .put("mtu", 1280)
            .put("password", passwordText.ifEmpty { prefs().getString("password", "") })
            .put("known_hosts", known)
            .put("accept_new_host_key", false)
    }

    private fun onNativeEvent(json: String) {
        val event = try {
            JSONObject(json)
        } catch (_: Exception) {
            append(json)
            return
        }
        when (event.optString("type")) {
            "status" -> setStatus(event.optString("status").replaceFirstChar { it.uppercase() })
            "log" -> append(event.optString("msg"))
            "error" -> {
                running = false
                setStatus("Error")
                append(event.optString("message") + " " + event.optString("hint"))
            }
            "exit" -> {
                running = false
                if (status.text == "Connecting" || status.text == "Reconnecting") setStatus("Disconnected")
                else connectButton.text = "Connect"
            }
            "host_key_prompt" -> askHostKey(event.optString("fingerprint"), event.optBoolean("changed"))
            "public_ip" -> append("public IP (${event.optString("phase")}): ${event.optString("value")}")
            "info" -> append(event.optString("transport") + " " + event.optString("server"))
            else -> append(json)
        }
    }

    private fun askHostKey(fingerprint: String, changed: Boolean) {
        val title = if (changed) "SSH host key changed" else "Trust this SSH server?"
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(fingerprint)
            .setNegativeButton("Reject") { _, _ -> NativeBridge.decide(0) }
            .setPositiveButton(if (changed) "Replace" else "Trust") { _, _ ->
                NativeBridge.decide(if (changed) 2 else 1)
            }
            .setOnCancelListener { NativeBridge.decide(0) }
            .show()
    }

    private fun setStatus(text: String) {
        status.text = text
        val color = when {
            text.startsWith("Connected") -> R.color.fox_green
            text.startsWith("Connecting") || text.startsWith("Reconnecting") -> R.color.fox_amber
            text.startsWith("Error") -> R.color.fox_red
            else -> R.color.fox_muted
        }
        status.setTextColor(getColor(color))
        connectButton.text = if (running) "Disconnect" else "Connect"
        connectButton.backgroundTintList = android.content.res.ColorStateList.valueOf(
            if (running) Color.parseColor("#C65A08") else Color.parseColor("#F27A1A")
        )
    }

    private fun append(line: String) {
        logs.append(line + "\n")
    }

    private fun loadRememberedPassword() {
        val saved = prefs().getString("password", null) ?: return
        if (password.text.isEmpty()) password.setText(saved)
    }

    private fun prefs() = EncryptedSharedPreferences.create(
        this,
        "fox-vpn-secrets",
        MasterKey.Builder(this).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    companion object {
        private const val REQUEST_VPN = 31
        @Suppress("unused")
        private val profileId = UUID.randomUUID().toString()
    }
}
