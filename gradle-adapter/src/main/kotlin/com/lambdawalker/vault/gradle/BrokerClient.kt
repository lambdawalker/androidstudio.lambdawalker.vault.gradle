package com.lambdawalker.vault.gradle

import com.lambdawalker.vault.protocol.*
import java.io.*
import java.util.concurrent.*

object BrokerClient {
    fun requestFrom(env: Map<String, String>, project: String, module: String, identity: String, variant: String): SigningIdentity? {
        if (env.keys.none { it.startsWith("LW_VAULT_") }) return null
        val endpoint = requireNotNull(env["LW_VAULT_PIPE"]) { "Missing signing broker endpoint." }
        require(endpoint.matches(Regex("\\\\\\\\\\.\\\\pipe\\\\lambdawalker-vault-[0-9a-f-]{36}"))) { "Invalid local signing broker endpoint." }
        val capability = requireNotNull(env["LW_VAULT_CAPABILITY"])
        require(capability.matches(Regex("[A-Za-z0-9_-]{43}")))
        val target = BuildTarget(requireNotNull(env["LW_VAULT_PROJECT"]), requireNotNull(env["LW_VAULT_MODULE"]),
            requireNotNull(env["LW_VAULT_VARIANT"]), requireNotNull(env["LW_VAULT_IDENTITY"]), requireNotNull(env["LW_VAULT_BUILD"]))
        require(target.project == project && target.module == module && target.identity == identity && target.variant == variant) { "Authorized signing target changed." }
        require(System.getProperty("os.name").startsWith("Windows")) { "Vault signing requires Windows 11." }
        RandomAccessFile(endpoint, "rw").use { pipe ->
            val timer = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "vault-broker-timeout").apply { isDaemon = true } }
            val timeout = timer.schedule({ runCatching { pipe.close() } }, 60, TimeUnit.SECONDS)
            try {
                Wire.writeRequest(DataOutputStream(FileOutputStream(pipe.fd)), capability, target)
                val result = Wire.readIdentity(DataInputStream(FileInputStream(pipe.fd)))
                try { pipe.writeByte(1); result.verify(); return result }
                catch (failure: Exception) { result.close(); throw failure }
            } finally { timeout.cancel(false); timer.shutdownNow() }
        }
    }
}
