package com.dreamshield.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class DreamShieldVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private val running = AtomicBoolean(false)
    private val pendingBlocked = AtomicLong(0L)
    private val store by lazy { BlocklistStore(this) }
    private val statsHandler = Handler(Looper.getMainLooper())
    private val flushTask = object : Runnable {
        override fun run() {
            flushBlocked()
            if (running.get()) statsHandler.postDelayed(this, 5_000)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopSelf(); return START_NOT_STICKY }
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, notification())
        if (!running.get()) startTunnel()
        return START_STICKY
    }

    private fun startTunnel() {
        try {
            val descriptor = Builder()
                .setSession("DreamShield DNS protection")
                .setMtu(1500)
                .addAddress("10.77.0.2", 32)
                .addDnsServer(DNS_GATEWAY)
                .addRoute(DNS_GATEWAY, 32)
                .setBlocking(true)
                .establish() ?: error("Android did not establish the VPN interface")
            tunnel = descriptor
            running.set(true)
            getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_RUNNING, true).apply()
            record("DNS protection connected")
            statsHandler.postDelayed(flushTask, 5_000)
            worker = Thread({ readPackets(descriptor) }, "DreamShield-DNS").apply { start() }
        } catch (e: Exception) {
            Log.e(TAG, "Could not start DNS tunnel", e)
            record("Could not start protection: ${e.javaClass.simpleName}")
            getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_RUNNING, false).apply()
            stopSelf()
        }
    }

    private fun readPackets(descriptor: ParcelFileDescriptor) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val output = FileOutputStream(descriptor.fileDescriptor)
        val packet = ByteArray(32767)
        val gateway = byteArrayOf(10, 77, 0, 1)
        try {
            while (running.get()) {
                val size = input.read(packet)
                if (size <= 0) continue
                val response = handle(packet.copyOf(size), gateway) ?: continue
                synchronized(output) { output.write(response); output.flush() }
            }
        } catch (e: Exception) {
            if (running.get()) {
                Log.w(TAG, "DNS tunnel reader stopped", e)
                record("DNS tunnel stopped: ${e.javaClass.simpleName}")
            }
        } finally {
            running.set(false)
            flushBlocked()
            getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_RUNNING, false).apply()
            stopSelf()
        }
    }

    internal fun handle(packet: ByteArray, gateway: ByteArray = byteArrayOf(10, 77, 0, 1)): ByteArray? {
        if (packet.size < 28 || (packet[0].toInt() ushr 4) != 4) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || packet.size < ihl + 8 || (packet[9].toInt() and 0xff) != 17) return null
        val fragment = ((packet[6].toInt() and 0xff) shl 8) or (packet[7].toInt() and 0xff)
        if ((fragment and 0x3fff) != 0 || (packet[ihl + 2].toInt() and 0xff) != 0 || (packet[ihl + 3].toInt() and 0xff) != 53) return null
        val udpLength = ((packet[ihl + 4].toInt() and 0xff) shl 8) or (packet[ihl + 5].toInt() and 0xff)
        if (udpLength < 20 || ihl + udpLength > packet.size) return null
        val dns = packet.copyOfRange(ihl + 8, ihl + udpLength)
        val query = DnsPacket.parseDns(dns) ?: return null
        if (store.rules().isBlocked(query.name)) {
            if (pendingBlocked.incrementAndGet() >= 25L) flushBlocked()
            val nxdomain = DnsPacket.dnsError(dns, query, 3)
            return DnsPacket.udpIpv4Response(packet, nxdomain, gateway)
        }
        return try {
            val answer = forwardDns(dns)
            DnsPacket.udpIpv4Response(packet, answer, gateway)
        } catch (e: Exception) {
            Log.w(TAG, "Upstream DNS failed", e)
            record("Upstream DNS unavailable; returned SERVFAIL")
            DnsPacket.udpIpv4Response(packet, DnsPacket.dnsError(dns, query, 2), gateway)
        }
    }

    private fun forwardDns(dns: ByteArray): ByteArray {
        var failure: Exception? = null
        for (resolver in UPSTREAMS) {
            try { return forwardDns(resolver, dns) } catch (e: Exception) { failure = e }
        }
        throw failure ?: IOException("No DNS upstream is configured")
    }

    private fun forwardDns(resolverHost: String, dns: ByteArray): ByteArray {
        DatagramSocket().use { socket ->
            check(protect(socket)) { "Could not protect DNS upstream socket from VPN routing" }
            socket.soTimeout = 4_000
            val remote = InetAddress.getByName(resolverHost)
            socket.connect(remote, 53)
            socket.send(DatagramPacket(dns, dns.size))
            val buffer = ByteArray(4096)
            val response = DatagramPacket(buffer, buffer.size)
            socket.receive(response)
            val answer = buffer.copyOf(response.length)
            validateDnsResponse(dns, answer)
            return if ((answer[2].toInt() and 0x02) != 0) forwardDnsTcp(resolverHost, dns) else answer
        }
    }

    private fun forwardDnsTcp(resolverHost: String, dns: ByteArray): ByteArray {
        Socket().use { socket ->
            check(protect(socket)) { "Could not protect DNS TCP socket from VPN routing" }
            socket.connect(InetSocketAddress(resolverHost, 53), 4_000)
            socket.soTimeout = 4_000
            DataOutputStream(socket.getOutputStream()).apply { writeShort(dns.size); write(dns); flush() }
            val input = DataInputStream(socket.getInputStream())
            val size = input.readUnsignedShort()
            check(size in 12..65_535) { "Invalid upstream DNS TCP response length" }
            val answer = ByteArray(size)
            input.readFully(answer)
            validateDnsResponse(dns, answer)
            return answer
        }
    }

    private fun validateDnsResponse(requestBytes: ByteArray, answer: ByteArray) {
        val request = DnsPacket.parseDns(requestBytes) ?: error("Invalid local DNS request")
        val response = DnsPacket.parseDns(answer) ?: error("Invalid upstream DNS response")
        check(response.id == request.id && response.name == request.name && response.type == request.type &&
            response.recordClass == request.recordClass && (response.flags and 0x8000) != 0) { "Mismatched upstream DNS response" }
    }

    private fun flushBlocked() {
        val count = pendingBlocked.getAndSet(0L)
        if (count == 0L) return
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        prefs.edit().putLong(KEY_BLOCKED, prefs.getLong(KEY_BLOCKED, 0L) + count).apply()
    }

    @Synchronized private fun record(message: String) {
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        val previous = prefs.getString(KEY_LOG, "") ?: ""
        prefs.edit().putString(KEY_LOG, ("${System.currentTimeMillis()}|$message\n$previous").lineSequence().take(40).joinToString("\n")).apply()
    }

    private fun notification(): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("DreamShield is active")
            .setContentText("Filtering DNS ads and trackers on this device").setContentIntent(open).setOngoing(true).build()
        else @Suppress("DEPRECATION") Notification.Builder(this).setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("DreamShield is active").setContentText("Filtering DNS ads and trackers")
            .setContentIntent(open).setOngoing(true).build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(CHANNEL, "Protection status", NotificationManager.IMPORTANCE_LOW))
    }

    override fun onRevoke() { record("VPN permission revoked"); stopSelf(); super.onRevoke() }
    override fun onDestroy() {
        running.set(false)
        statsHandler.removeCallbacks(flushTask)
        flushBlocked()
        try { tunnel?.close() } catch (_: Exception) { }
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_RUNNING, false).apply()
        record("DNS protection disconnected")
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "com.dreamshield.app.STOP"
        const val PREFS = "protection"
        const val KEY_RUNNING = "running"
        const val KEY_BLOCKED = "blocked"
        const val KEY_LOG = "diagnostics"
        private const val TAG = "DreamShield"
        private const val DNS_GATEWAY = "10.77.0.1"
        private val UPSTREAMS = listOf("9.9.9.9", "149.112.112.112")
        private const val CHANNEL = "dreamshield_protection"
        private const val NOTIFICATION_ID = 7001
    }
}
