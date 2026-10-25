package com.dreamshield.app

/** Minimal DNS-over-UDP parser and response builder for IPv4 packets from Android's TUN. */
internal object DnsPacket {
    data class Query(val id: Int, val name: String, val questionEnd: Int, val flags: Int, val type: Int, val recordClass: Int)

    fun parseDns(dns: ByteArray): Query? {
        if (dns.size < 12) return null
        val qd = u16(dns, 4)
        if (qd != 1) return null
        val labels = ArrayList<String>()
        var p = 12
        while (p < dns.size) {
            val n = dns[p++].toInt() and 0xff
            if (n == 0) break
            if (n and 0xc0 != 0 || n > 63 || p + n > dns.size) return null
            val label = dns.copyOfRange(p, p + n).toString(Charsets.US_ASCII)
            if (!label.matches(Regex("[A-Za-z0-9_-]{1,63}"))) return null
            labels += label.lowercase()
            p += n
        }
        if (p + 4 > dns.size || labels.isEmpty()) return null
        return Query(u16(dns, 0), labels.joinToString("."), p + 4, u16(dns, 2), u16(dns, p), u16(dns, p + 2))
    }

    fun dnsError(dns: ByteArray, query: Query, rcode: Int): ByteArray {
        val out = dns.copyOfRange(0, query.questionEnd)
        put16(out, 2, (query.flags and 0x7910) or 0x8080 or (query.flags and 0x0100) or rcode)
        put16(out, 4, 1); put16(out, 6, 0); put16(out, 8, 0); put16(out, 10, 0)
        return out
    }

    fun udpIpv4Response(packet: ByteArray, dns: ByteArray, resolver: ByteArray): ByteArray? {
        if (packet.size < 28 || packet[0].toInt() ushr 4 != 4) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || packet.size < ihl + 8) return null
        val source = packet.copyOfRange(12, 16)
        val out = ByteArray(ihl + 8 + dns.size)
        packet.copyInto(out, 0, 0, ihl)
        out[2] = (out.size ushr 8).toByte(); out[3] = out.size.toByte()
        resolver.copyInto(out, 12)
        source.copyInto(out, 16)
        out[ihl] = packet[ihl + 2]; out[ihl + 1] = packet[ihl + 3]
        out[ihl + 2] = packet[ihl]; out[ihl + 3] = packet[ihl + 1]
        val udpLen = 8 + dns.size
        out[ihl + 4] = (udpLen ushr 8).toByte(); out[ihl + 5] = udpLen.toByte()
        dns.copyInto(out, ihl + 8)
        out[10] = 0; out[11] = 0
        put16(out, 10, checksum(out, 0, ihl))
        out[ihl + 6] = 0; out[ihl + 7] = 0
        put16(out, ihl + 6, udpChecksum(out, ihl, udpLen))
        return out
    }

    private fun udpChecksum(p: ByteArray, udp: Int, len: Int): Int {
        var sum = 0L
        for (i in 12 until 20 step 2) sum += u16(p, i).toLong()
        sum += 17L + len
        sum += checksumSum(p, udp, len)
        val value = ((sum and 0xffff) + (sum ushr 16)).let { (it and 0xffff) + (it ushr 16) }
        return (value.toInt().inv() and 0xffff).let { if (it == 0) 0xffff else it }
    }

    private fun checksum(p: ByteArray, start: Int, len: Int): Int {
        var sum = checksumSum(p, start, len)
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun checksumSum(p: ByteArray, start: Int, len: Int): Long {
        var sum = 0L; var i = start
        while (i + 1 < start + len) { sum += u16(p, i); i += 2 }
        if (i < start + len) sum += (p[i].toInt() and 0xff) shl 8
        return sum
    }

    private fun u16(p: ByteArray, i: Int) = ((p[i].toInt() and 0xff) shl 8) or (p[i + 1].toInt() and 0xff)
    private fun put16(p: ByteArray, i: Int, value: Int) { p[i] = (value ushr 8).toByte(); p[i + 1] = value.toByte() }
}
