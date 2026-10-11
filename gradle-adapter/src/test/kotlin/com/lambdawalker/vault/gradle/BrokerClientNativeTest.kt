package com.lambdawalker.vault.gradle

import com.lambdawalker.vault.protocol.*
import com.lambdawalker.vault.protocol.NamedPipeServer
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.util.concurrent.*
import kotlin.test.*

@EnabledOnOs(OS.WINDOWS)
class BrokerClientNativeTest {
    @TempDir lateinit var dir: Path
    @Test fun `adapter obtains and verifies a real identity through private Windows pipe`() {
        val key = dir.resolve("disposable.p12")
        val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool.exe")
        val process = ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "fixture", "-keyalg", "RSA", "-keysize", "2048",
            "-dname", "CN=Disposable", "-validity", "1", "-storetype", "PKCS12", "-keystore", key.toString(), "-storepass", "disposable-test-password")
            .redirectErrorStream(true).start()
        process.inputStream.readAllBytes(); assertEquals(0, process.waitFor())
        val identity = SigningIdentity.import("fixture", key, "PKCS12", "fixture", "disposable-test-password".toCharArray(), "disposable-test-password".toCharArray())
        val target = BuildTarget(dir.toRealPath().toString(), ":app", "debug", "fixture", "build")
        val grants = GrantRegistry(); val pool = Executors.newSingleThreadExecutor()
        try {
            NamedPipeServer().use { pipe ->
                val capability = grants.issue(target, identity)
                val serving = pool.submit { pipe.serve { grants.redeem(it.capability, it.target) } }
                val env = BuildInvocation(target, capability, pipe.endpoint).environment
                requireNotNull(BrokerClient.requestFrom(env, target.project, target.module, target.identity, target.variant)).use {
                    assertEquals(identity.fingerprint, it.fingerprint); it.verify()
                }
                serving.get(5, TimeUnit.SECONDS)
                assertFails { grants.redeem(capability, target) }
            }
        } finally { grants.close(); identity.close(); pool.shutdownNow() }
    }
}
