package com.lambdawalker.vault.protocol

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class SigningIdentityTest {
    @TempDir lateinit var dir: Path

    @Test fun `import verifies private key password and certificate without modifying keystore`() {
        val file = dir.resolve("disposable.p12")
        val keytool = Path.of(System.getProperty("java.home"), "bin", if (System.getProperty("os.name").startsWith("Windows")) "keytool.exe" else "keytool")
        val process = ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "test", "-keyalg", "RSA",
            "-keysize", "2048", "-dname", "CN=Disposable Test", "-validity", "1", "-storetype", "PKCS12",
            "-keystore", file.toString(), "-storepass", "throwaway-test-password", "-keypass", "throwaway-test-password")
            .redirectErrorStream(true).start()
        process.inputStream.readAllBytes()
        assertEquals(0, process.waitFor())
        val before = Files.readAllBytes(file)
        SigningIdentity.import("test", file, "PKCS12", "test", "throwaway-test-password".toCharArray(), "throwaway-test-password".toCharArray()).use {
            assertEquals(64, it.fingerprint.length)
            it.verify()
            val relocated = dir.resolve("restored.p12")
            Files.copy(file, relocated)
            it.relocate(relocated).use { restored ->
                assertEquals(it.fingerprint, restored.fingerprint)
                assertEquals(relocated.toRealPath().toString(), restored.path)
                restored.verify()
            }
        }
        assertContentEquals(before, Files.readAllBytes(file))
        assertFails { SigningIdentity.import("test", file, "PKCS12", "test", "wrong-password".toCharArray(), "wrong-password".toCharArray()) }
    }
}
