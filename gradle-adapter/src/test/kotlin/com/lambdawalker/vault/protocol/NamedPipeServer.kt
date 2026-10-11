// Test-only reference broker copied from Studio protocol v1.
package com.lambdawalker.vault.protocol

import com.lambdawalker.vault.protocol.*
import com.sun.jna.*
import com.sun.jna.ptr.*
import com.sun.jna.win32.StdCallLibrary
import com.sun.jna.platform.win32.*
import java.io.*
import java.util.UUID
import java.util.concurrent.TimeUnit

/** One private, local-only pipe per operation. Nonblocking native calls allow bounded cancellation. */
class NamedPipeServer : AutoCloseable {
    val endpoint = "\\\\.\\pipe\\lambdawalker-vault-${UUID.randomUUID()}"
    private var handle: WinNT.HANDLE? = null
    private val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
    private interface SecurityApi : StdCallLibrary {
        fun ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: WString, revision: Int, result: PointerByReference, size: IntByReference?): Boolean
    }
    init {
        check(Platform.isWindows()) { "The signing broker requires Windows 11." }
        val token = WinNT.HANDLEByReference()
        check(Advapi32.INSTANCE.OpenProcessToken(Kernel32.INSTANCE.GetCurrentProcess(), WinNT.TOKEN_QUERY, token)) { "Cannot inspect Windows user." }
        val sid = try { Advapi32Util.getTokenAccount(token.value).sidString } finally { Kernel32.INSTANCE.CloseHandle(token.value) }
        val descriptor = PointerByReference()
        val api = Native.load("Advapi32", SecurityApi::class.java)
        check(api.ConvertStringSecurityDescriptorToSecurityDescriptorW(WString("D:P(A;;GA;;;$sid)(A;;GA;;;BA)"), 1, descriptor, null)) { "Cannot secure signing pipe." }
        try {
            val attributes = WinBase.SECURITY_ATTRIBUTES().apply {
                dwLength = WinDef.DWORD(size().toLong()); lpSecurityDescriptor = descriptor.value; bInheritHandle = false
            }
            val created = Kernel32.INSTANCE.CreateNamedPipe(endpoint, 3 or 0x00080000, 1 or 8, 1, 65536, 65536, 0, attributes)
            check(created != WinBase.INVALID_HANDLE_VALUE) { "Cannot create private signing pipe." }
            handle = created
        } finally { Kernel32.INSTANCE.LocalFree(descriptor.value) }
    }
    fun serve(redeem: (BuildProof) -> SigningIdentity) {
        try {
            while (!connect()) pause()
            val input = DataInputStream(object : InputStream() {
                override fun read(): Int { val one = ByteArray(1); return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 255 }
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                    if (length == 0) return 0
                    val temporary = ByteArray(length.coerceAtMost(65536))
                    try {
                        while (true) {
                            val read = readNative(temporary)
                            if (read > 0) { temporary.copyInto(bytes, offset, 0, read); return read }
                            pause()
                        }
                    } finally { temporary.fill(0) }
                }
            })
            val output = DataOutputStream(object : OutputStream() {
                override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                    var sent = 0
                    while (sent < length) {
                        val temporary = bytes.copyOfRange(offset + sent, offset + minOf(length, sent + 65536))
                        try { val count = writeNative(temporary); if (count == 0) pause() else sent += count }
                        finally { temporary.fill(0) }
                    }
                }
            })
            val proof = Wire.readRequest(input)
            try { redeem(proof).use { Wire.writeIdentity(output, it) } }
            catch (_: Exception) { runCatching { Wire.writeFailure(output) } }
            // Wait for client acknowledgement so closing a byte pipe cannot discard its response.
            check(input.readUnsignedByte() == 1) { "Signing client disconnected." }
        } finally { close() }
    }
    @Synchronized private fun current(): WinNT.HANDLE = handle ?: throw IOException("Signing pipe closed.")
    @Synchronized private fun connect(): Boolean {
        if (Kernel32.INSTANCE.ConnectNamedPipe(current(), null)) return true
        return when (Native.getLastError()) { 535 -> true; 536 -> false; else -> throw IOException("Signing pipe connection failed.") }
    }
    @Synchronized private fun readNative(bytes: ByteArray): Int {
        val count = IntByReference()
        if (!Kernel32.INSTANCE.ReadFile(current(), bytes, bytes.size, count, null) && Native.getLastError() != 232)
            throw IOException("Signing pipe read failed.")
        return count.value
    }
    @Synchronized private fun writeNative(bytes: ByteArray): Int {
        val count = IntByReference()
        check(Kernel32.INSTANCE.WriteFile(current(), bytes, bytes.size, count, null)) { "Signing pipe write failed." }
        return count.value
    }
    private fun pause() {
        current()
        if (System.nanoTime() - deadline >= 0) throw IOException("Signing authorization timed out.")
        Thread.sleep(10)
    }
    @Synchronized override fun close() {
        handle?.let { Kernel32.INSTANCE.DisconnectNamedPipe(it); Kernel32.INSTANCE.CloseHandle(it) }
        handle = null
    }
}
