package com.lambdawalker.vault.protocol

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey

/** Owns the supplied password buffers; callers transfer ownership and must close the identity. */
class SigningIdentity(
    val id: String, val path: String, val storeType: String, val alias: String, val fingerprint: String,
    val storePassword: CharArray, val keyPassword: CharArray,
) : AutoCloseable {
    init {
        require(id.matches(Regex("[A-Za-z0-9_-]{1,64}"))) { "Invalid identity ID." }
        require(storeType == "JKS" || storeType == "PKCS12") { "Choose JKS or PKCS12." }
        require(alias.isNotBlank() && path.isNotBlank()) { "Keystore path and alias are required." }
        require(fingerprint.matches(Regex("[0-9a-f]{64}"))) { "Invalid certificate fingerprint." }
    }
    fun copyOwned() = SigningIdentity(id, path, storeType, alias, fingerprint, storePassword.copyOf(), keyPassword.copyOf())
    fun relocate(file: Path): SigningIdentity {
        val restored = import(id, file, storeType, alias, storePassword, keyPassword)
        if (restored.fingerprint != fingerprint) { restored.close(); error("Restored keystore certificate does not match.") }
        return restored
    }
    fun verify() {
        val file = Path.of(path)
        require(!Files.isSymbolicLink(file) && file.toRealPath().toString() == path) { "Keystore path changed." }
        require(readFingerprint(file, storeType, alias, storePassword, keyPassword) == fingerprint) { "Keystore certificate changed." }
    }
    override fun close() { storePassword.fill('\u0000'); keyPassword.fill('\u0000') }
    override fun toString() = "SigningIdentity(redacted)"

    companion object {
        fun import(id: String, file: Path, type: String, alias: String, storePassword: CharArray, keyPassword: CharArray): SigningIdentity {
            require(!Files.isSymbolicLink(file) && Files.isRegularFile(file, NOFOLLOW_LINKS)) { "Select a regular keystore file." }
            val canonical = file.toRealPath()
            val fingerprint = readFingerprint(canonical, type, alias, storePassword, keyPassword)
            return SigningIdentity(id, canonical.toString(), type, alias, fingerprint, storePassword.copyOf(), keyPassword.copyOf())
        }
        private fun readFingerprint(file: Path, type: String, alias: String, storePassword: CharArray, keyPassword: CharArray): String {
            require(type in setOf("JKS", "PKCS12"))
            try {
                require(Files.size(file) <= 16 * 1024 * 1024) { "Keystore is too large." }
                val store = KeyStore.getInstance(type)
                Files.newInputStream(file).use { store.load(it, storePassword) }
                require(store.getKey(alias, keyPassword) is PrivateKey) { "Alias is not a private signing key." }
                return MessageDigest.getInstance("SHA-256").digest(store.getCertificate(alias).encoded).toHex()
            } catch (_: Exception) { throw IllegalArgumentException("Unable to open signing identity. Check type, alias and passwords.") }
        }
    }
}
