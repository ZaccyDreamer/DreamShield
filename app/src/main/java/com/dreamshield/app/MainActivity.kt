package com.dreamshield.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val store by lazy { BlocklistStore(this) }
    private val executor = Executors.newSingleThreadExecutor()
    private lateinit var status: TextView
    private lateinit var stats: TextView
    private lateinit var logs: TextView
    private lateinit var protectionSwitch: Switch
    private var updatingSwitch = false
    private lateinit var allowInput: EditText
    private lateinit var blockInput: EditText
    private val statusHandler = Handler(Looper.getMainLooper())
    private val refreshTask = object : Runnable {
        override fun run() {
            if (::status.isInitialized) refreshStatus()
            statusHandler.postDelayed(this, 2_000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showOnboardingIfNeeded()
        render()
    }

    private fun render() {
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 32, 24, 20); setBackgroundColor(0xfff4f7fb.toInt()) }
        val scroll = ScrollView(this)
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER_HORIZONTAL }
        scroll.addView(content)
        content.addView(TextView(this).apply { text = "DreamShield"; textSize = 30f; setTextColor(0xff16345f.toInt()); gravity = Gravity.CENTER })
        content.addView(TextView(this).apply { text = "Private DNS protection for your phone"; textSize = 15f; setTextColor(0xff53657b.toInt()); gravity = Gravity.CENTER; setPadding(0, 4, 0, 22) })
        status = TextView(this).apply { textSize = 18f; gravity = Gravity.CENTER; setPadding(12, 16, 12, 16) }
        content.addView(status, match())
        protectionSwitch = Switch(this).apply {
            text = "Enable DNS protection"
            textSize = 17f
            setPadding(12, 8, 12, 8)
            setOnCheckedChangeListener { _, checked ->
                if (updatingSwitch) return@setOnCheckedChangeListener
                if (checked) requestStart() else stopProtection()
            }
        }
        content.addView(protectionSwitch, match())
        stats = TextView(this).apply { textSize = 16f; setPadding(4, 20, 4, 14) }
        content.addView(stats)
        content.addView(TextView(this).apply { text = "Blocklist: AdGuard DNS filter"; textSize = 17f; setTextColor(0xff16345f.toInt()) })
        content.addView(TextView(this).apply { text = "DNS-compatible rules from the maintained AdGuard DNS filter. Updating uses HTTPS; the list is stored locally."; textSize = 14f; setTextColor(0xff53657b.toInt()); setPadding(0, 6, 0, 8) })
        content.addView(Button(this).apply { text = "Update blocklist"; setOnClickListener { updateList() } }, match())
        content.addView(TextView(this).apply { text = "Allowlist (one domain per line)"; textSize = 16f; setPadding(0, 16, 0, 4) })
        allowInput = editor(store.allowText())
        content.addView(allowInput, ViewGroup.LayoutParams(-1, 120))
        content.addView(TextView(this).apply { text = "Custom blocklist (one domain per line)"; textSize = 16f; setPadding(0, 12, 0, 4) })
        blockInput = editor(store.customText())
        content.addView(blockInput, ViewGroup.LayoutParams(-1, 120))
        content.addView(Button(this).apply { text = "Save domain rules"; setOnClickListener { saveRules() } }, match())
        content.addView(TextView(this).apply { text = "Recent diagnostics"; textSize = 17f; setPadding(0, 16, 0, 4) })
        logs = TextView(this).apply { textSize = 12f; setTextColor(0xff53657b.toInt()) }
        content.addView(logs)
        content.addView(TextView(this).apply {
            text = "DNS filtering cannot remove ads served from the same domains as video or page content. YouTube app ads, encrypted DNS, VPN conflicts, and browser-specific protection may bypass these rules. DreamShield does not inspect HTTPS traffic or save queried domain names."
            textSize = 13f; setTextColor(0xff53657b.toInt()); setPadding(0, 20, 0, 14)
        })
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)
        refreshStatus()
    }

    private fun editor(value: String) = EditText(this).apply {
        setText(value); textSize = 14f; gravity = Gravity.TOP; setPadding(12, 10, 12, 10)
        setBackgroundColor(0xffffffff.toInt()); hint = "example.com"; isSingleLine = false
    }

    @Suppress("DEPRECATION")
    private fun requestStart() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_REQUEST)
            return
        }
        requestVpnAuthorization()
    }

    private fun requestVpnAuthorization() {
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, VPN_REQUEST)
        else startVpnService()
    }

    @Suppress("DEPRECATION")
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == NOTIFICATION_REQUEST) requestVpnAuthorization()
    }

    @Deprecated("Android VPN permission result callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST && resultCode == RESULT_OK) startVpnService()
        else Toast.makeText(this, "VPN permission is needed to filter DNS", Toast.LENGTH_LONG).show()
    }

    private fun startVpnService() {
        val intent = Intent(this, DreamShieldVpnService::class.java)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        status.postDelayed({ refreshStatus() }, 800)
    }

    private fun stopProtection() {
        startService(Intent(this, DreamShieldVpnService::class.java).setAction(DreamShieldVpnService.ACTION_STOP))
        status.postDelayed({ refreshStatus() }, 500)
    }

    private fun updateList() {
        Toast.makeText(this, "Downloading DNS blocklist…", Toast.LENGTH_SHORT).show()
        executor.execute {
            val result = store.update()
            runOnUiThread {
                val message = result.fold({ "Updated ${it} domain rules" }, { "Update failed; cached rules retained (${it.message ?: "network error"})" })
                Toast.makeText(this, message, Toast.LENGTH_LONG).show(); refreshStatus()
            }
        }
    }

    private fun saveRules() {
        store.saveAllow(allowInput.text.toString())
        store.saveCustom(blockInput.text.toString())
        Toast.makeText(this, "Domain rules saved", Toast.LENGTH_SHORT).show()
    }

    private fun refreshStatus() {
        val prefs = getSharedPreferences(DreamShieldVpnService.PREFS, MODE_PRIVATE)
        val active = prefs.getBoolean(DreamShieldVpnService.KEY_RUNNING, false)
        status.text = if (active) "● Protection active" else "○ Protection stopped"
        status.setTextColor(if (active) 0xff178451.toInt() else 0xff8a4751.toInt())
        if (protectionSwitch.isChecked != active) {
            updatingSwitch = true
            protectionSwitch.isChecked = active
            updatingSwitch = false
        }
        stats.text = "Blocked DNS requests: ${prefs.getLong(DreamShieldVpnService.KEY_BLOCKED, 0L)}\nBlocklist updated: ${store.listUpdatedAt().takeIf { it > 0 }?.let { DateFormat.getDateTimeInstance().format(Date(it)) } ?: "Not yet"}"
        logs.text = (prefs.getString(DreamShieldVpnService.KEY_LOG, "") ?: "No diagnostic events yet")
            .lineSequence().filter { it.isNotBlank() }.take(10).joinToString("\n") { line ->
                val parts = line.split('|', limit = 2)
                if (parts.size == 2) "${DateFormat.getTimeInstance().format(Date(parts[0].toLongOrNull() ?: 0L))}  ${parts[1]}" else line
            }
    }

    private fun showOnboardingIfNeeded() {
        val prefs = getSharedPreferences("onboarding", MODE_PRIVATE)
        if (prefs.getBoolean("seen", false)) return
        android.app.AlertDialog.Builder(this)
            .setTitle("How DreamShield works")
            .setMessage("DreamShield creates a local Android VPN to route DNS requests through an on-device filter. Android will show a VPN permission prompt and a persistent notification. Unblocked DNS requests are sent to Quad9 (9.9.9.9); queried domains are not logged or uploaded by DreamShield. HTTPS content is never inspected.\n\nDNS filtering reduces many ads and trackers, but cannot reliably remove ads served by the same domains as content. YouTube app ads may remain. Browsers or apps using encrypted DNS can bypass the filter. Only one VPN can be active at a time.")
            .setPositiveButton("Understood") { _, _ -> prefs.edit().putBoolean("seen", true).apply() }
            .setOnCancelListener { prefs.edit().putBoolean("seen", true).apply() }.show()
    }

    private fun match() = LinearLayout.LayoutParams(-1, ViewGroup.LayoutParams.WRAP_CONTENT)
    override fun onResume() { super.onResume(); statusHandler.post(refreshTask) }
    override fun onPause() { statusHandler.removeCallbacks(refreshTask); super.onPause() }
    override fun onDestroy() { statusHandler.removeCallbacks(refreshTask); executor.shutdownNow(); super.onDestroy() }

    companion object { private const val VPN_REQUEST = 42; private const val NOTIFICATION_REQUEST = 43 }
}
