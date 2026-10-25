package com.dreamshield.app

import android.content.Context
import android.util.Log
import java.net.URL
import javax.net.ssl.HttpsURLConnection

internal class BlocklistStore(private val context: Context) {
    private val prefs = context.getSharedPreferences("rules", Context.MODE_PRIVATE)
    @Volatile private var cachedFeed: DomainRules.FilterRules? = null
    @Volatile private var cachedRules: DomainRules? = null
    private val listener = android.content.SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == "feed" || key == "allow" || key == "custom") {
            synchronized(this) {
                if (key == "feed") cachedFeed = null
                cachedRules = null
            }
        }
    }

    init { prefs.registerOnSharedPreferenceChangeListener(listener) }

    private fun loadRules(): DomainRules {
        val feed = cachedFeed ?: DomainRules.parseFilter(prefs.getString("feed", "") ?: "").also { cachedFeed = it }
        val allow = DomainRules.parse(prefs.getString("allow", "") ?: "") + feed.allowed
        return DomainRules(feed.blocked, allow, DomainRules.parse(prefs.getString("custom", "") ?: ""))
    }
    fun rules(): DomainRules = cachedRules ?: synchronized(this) {
        cachedRules ?: loadRules().also { cachedRules = it }
    }
    fun allowText() = prefs.getString("allow", "") ?: ""
    fun customText() = prefs.getString("custom", "") ?: ""
    fun saveAllow(value: String) { prefs.edit().putString("allow", value).apply() }
    fun saveCustom(value: String) { prefs.edit().putString("custom", value).apply() }
    fun listUpdatedAt() = prefs.getLong("updated", 0L)

    fun update(): Result<Int> = runCatching {
        val connection = (URL(FEED_URL).openConnection() as HttpsURLConnection).apply {
            connectTimeout = 12_000; readTimeout = 20_000; requestMethod = "GET"
            setRequestProperty("User-Agent", "DreamShield/1.0 (DNS filtering)")
        }
        try {
            check(connection.responseCode == 200) { "Blocklist server returned HTTP ${connection.responseCode}" }
            val body = connection.inputStream.bufferedReader().use { reader ->
                val out = StringBuilder()
                val buffer = CharArray(8192)
                while (true) {
                    val count = reader.read(buffer)
                    if (count < 0) break
                    check(out.length + count <= MAX_LIST_CHARS) { "Blocklist exceeded the 8 MiB safety limit" }
                    out.append(buffer, 0, count)
                }
                out.toString()
            }
            val parsed = DomainRules.parse(body)
            check(parsed.size > 1000) { "Downloaded list did not contain enough valid domain rules" }
            prefs.edit().putString("feed", body).putLong("updated", System.currentTimeMillis()).apply()
            parsed.size
        } finally { connection.disconnect() }
    }.onFailure { Log.w("DreamShield", "Blocklist update failed; keeping cached list", it) }

    companion object {
        const val FEED_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
        private const val MAX_LIST_CHARS = 8 * 1024 * 1024
    }
}
