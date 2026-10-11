package com.lambdawalker.vault.protocol
import java.io.*
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
internal const val MAX_FIELD_SIZE = 16_384
internal class WipingOutput : ByteArrayOutputStream() {
    override fun close() { buf.fill(0); reset() }
}
internal fun binary(write: DataOutputStream.() -> Unit): ByteArray = WipingOutput().use { bytes ->
    DataOutputStream(bytes).apply(write).flush(); bytes.toByteArray()
}
internal fun DataInputStream.bytes(size: Int): ByteArray {
    require(size >= 0 && size <= available()) { "Malformed vault." }
    return ByteArray(size).also(::readFully)
}
internal fun DataOutputStream.field(value: ByteArray) { require(value.size <= MAX_FIELD_SIZE); writeInt(value.size); write(value) }
internal fun DataInputStream.field(): ByteArray { val size = readInt(); require(size in 0..MAX_FIELD_SIZE); return bytes(size) }

internal object Payload {
    fun encode(identities: List<SigningIdentity>): ByteArray = binary {
        require(identities.size <= 64 && identities.map { it.id }.distinct().size == identities.size)
        writeInt(identities.size)
        identities.forEach { identity ->
            listOf(identity.id, identity.path, identity.storeType, identity.alias, identity.fingerprint).forEach { field(it.toByteArray(Charsets.UTF_8)) }
            listOf(identity.storePassword, identity.keyPassword).forEach { password ->
                val bytes = encodeSecret(password); try { field(bytes) } finally { bytes.fill(0) }
            }
        }
    }
    fun decode(bytes: ByteArray): MutableList<SigningIdentity> {
        val input = DataInputStream(ByteArrayInputStream(bytes))
        val count = input.readInt(); require(count in 0..64)
        val result = mutableListOf<SigningIdentity>()
        try {
            repeat(count) {
                val fields = (0..4).map { val raw = input.field(); try { String(decodeSecret(raw)) } finally { raw.fill(0) } }
                val passwords = mutableListOf<CharArray>()
                try {
                    repeat(2) { val raw = input.field(); try { passwords += decodeSecret(raw) } finally { raw.fill(0) } }
                    result += SigningIdentity(fields[0], fields[1], fields[2], fields[3], fields[4], passwords[0], passwords[1])
                } catch (failure: Exception) { passwords.forEach { it.fill('\u0000') }; throw failure }
            }
            require(input.available() == 0 && result.map { it.id }.distinct().size == count)
            return result
        } catch (failure: Exception) { result.forEach(SigningIdentity::close); throw failure }
    }
}
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 255) }

internal fun encodeSecret(chars: CharArray): ByteArray {
    val buffer = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).encode(CharBuffer.wrap(chars))
    return try { ByteArray(buffer.remaining()).also(buffer::get) }
    finally { if (buffer.hasArray()) buffer.array().fill(0) }
}

internal fun decodeSecret(bytes: ByteArray): CharArray {
    val buffer = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes))
    return try { CharArray(buffer.remaining()).also(buffer::get) }
    finally { if (buffer.hasArray()) buffer.array().fill('\u0000') }
}

data class BuildTarget(val project: String, val module: String, val variant: String, val identity: String, val buildId: String)
