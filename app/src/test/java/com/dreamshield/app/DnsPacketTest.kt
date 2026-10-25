package com.dreamshield.app

import org.junit.Assert.*
import org.junit.Test

class DnsPacketTest {
    @Test fun parsesQuestionAndBuildsNxdomain() {
        val query = dnsQuery("ads.example")
        val parsed = DnsPacket.parseDns(query)!!
        assertEquals("ads.example", parsed.name)
        val response = DnsPacket.dnsError(query, parsed, 3)
        assertEquals(query[0], response[0]); assertEquals(query[1], response[1])
        assertEquals(0x83, response[3].toInt() and 0xff)
        assertEquals(0, response[7].toInt())
        assertEquals(query.size, response.size)
    }

    @Test fun returnsValidIpv4UdpPacketWithSwappedEndpoints() {
        val dns = dnsQuery("safe.example")
        val request = ipv4Udp(dns)
        val resolver = byteArrayOf(10, 77, 0, 1)
        val response = DnsPacket.udpIpv4Response(request, dns, resolver)!!
        assertArrayEquals(resolver, response.copyOfRange(12, 16))
        assertArrayEquals(request.copyOfRange(12, 16), response.copyOfRange(16, 20))
        assertEquals(0, internetChecksum(response, 0, 20))
        assertEquals(0, udpChecksum(response, 20, response.size - 20))
    }

    private fun dnsQuery(name: String): ByteArray {
        val labels = name.split('.').flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() }.toByteArray()
        return byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) + labels + byteArrayOf(0, 0, 1, 0, 1)
    }

    private fun ipv4Udp(dns: ByteArray): ByteArray {
        val p = ByteArray(28 + dns.size)
        p[0] = 0x45; p[2] = (p.size ushr 8).toByte(); p[3] = p.size.toByte(); p[8] = 64; p[9] = 17
        p[12] = 10; p[15] = 2; p[16] = 10; p[19] = 77
        p[20] = 0x30; p[21] = 0x39; p[22] = 0; p[23] = 53
        val udpLength = 8 + dns.size
        p[24] = (udpLength ushr 8).toByte(); p[25] = udpLength.toByte()
        dns.copyInto(p, 28)
        return p
    }

    private fun internetChecksum(p: ByteArray, start: Int, length: Int): Int {
        var sum = 0L; var i = start
        while (i + 1 < start + length) { sum += ((p[i].toInt() and 255) shl 8) + (p[i + 1].toInt() and 255); i += 2 }
        while (sum ushr 16 != 0L) sum = (sum and 65535) + (sum ushr 16)
        return sum.toInt().inv() and 65535
    }

    private fun udpChecksum(p: ByteArray, start: Int, length: Int): Int {
        var sum = 0L
        for (i in 12 until 20 step 2) sum += ((p[i].toInt() and 255) shl 8) + (p[i + 1].toInt() and 255)
        sum += 17 + length
        var i = start
        while (i + 1 < start + length) { sum += ((p[i].toInt() and 255) shl 8) + (p[i + 1].toInt() and 255); i += 2 }
        if (i < start + length) sum += (p[i].toInt() and 255) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 65535) + (sum ushr 16)
        return sum.toInt().inv() and 65535
    }
}
