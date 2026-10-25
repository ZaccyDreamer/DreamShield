package com.dreamshield.app

internal class DomainRules(
    private val blocked: Set<String>,
    private val allowed: Set<String>,
    private val customBlocked: Set<String>
) {
    data class FilterRules(val blocked: Set<String>, val allowed: Set<String>)

    fun isBlocked(domain: String): Boolean {
        val host = domain.trim('.').lowercase()
        if (matches(host, allowed)) return false
        return matches(host, blocked) || matches(host, customBlocked)
    }

    private fun matches(host: String, rules: Set<String>): Boolean {
        var candidate = host
        while (candidate.isNotEmpty()) {
            if (candidate in rules) return true
            val dot = candidate.indexOf('.')
            if (dot < 0) break
            candidate = candidate.substring(dot + 1)
        }
        return false
    }

    companion object {
        fun parse(text: String): Set<String> = parseFilter(text).blocked

        fun parseFilter(text: String): FilterRules {
            val blocked = LinkedHashSet<String>()
            val allowed = LinkedHashSet<String>()
            text.lineSequence().forEach { source ->
                val raw = source.substringBefore('#').trim()
                if (raw.isEmpty() || raw.startsWith('!') || raw.startsWith('[')) return@forEach
                val exception = raw.startsWith("@@||")
                if (raw.startsWith("@@") && !exception) return@forEach
                val options = raw.substringAfter('$', "")
                if (options.split(',').any { it.startsWith("dnstype=") || it.startsWith("client=") || it.startsWith("ctag=") || it.startsWith("dnsrewrite=") || it == "badfilter" }) return@forEach
                if (raw.startsWith("0.0.0.0 ") || raw.startsWith("127.0.0.1 ")) {
                    raw.substringAfter(' ').split(Regex("\\s+")).forEach { host -> addIfDomain(host, blocked) }
                    return@forEach
                }
                val candidate = when {
                    exception -> raw.removePrefix("@@||").removePrefix("*.").substringBefore('^').substringBefore('/').substringBefore('$')
                    raw.startsWith("||") -> raw.removePrefix("||").removePrefix("*.").substringBefore('^').substringBefore('/').substringBefore('$')
                    raw.matches(Regex("[A-Za-z0-9_.-]+")) -> raw
                    else -> return@forEach
                }.trim('.').lowercase()
                if (candidate.isDomain()) (if (exception) allowed else blocked).add(candidate)
            }
            return FilterRules(blocked, allowed)
        }

        private fun addIfDomain(value: String, into: MutableSet<String>) {
            val candidate = value.trim('.').lowercase()
            if (candidate.isDomain()) into.add(candidate)
        }

        private fun String.isDomain() = contains('.') && length <= 253 && split('.').all { it.isNotEmpty() && it.length <= 63 }
    }
}
