package com.lambdawalker.vault.gradle

import org.junit.jupiter.api.Test
import kotlin.test.*

class AdapterTest {
    @Test fun `missing broker environment cannot request passwords`() {
        assertNull(BrokerClient.requestFrom(emptyMap(), "/project", ":app", "dev", "debug"))
    }
    @Test fun `partial and remote broker endpoints are rejected`() {
        assertFails { BrokerClient.requestFrom(mapOf("LW_VAULT_CAPABILITY" to "a".repeat(43)), "/project", ":app", "dev", "debug") }
        assertFails { BrokerClient.requestFrom(mapOf("LW_VAULT_PIPE" to "\\\\remote\\pipe\\x", "LW_VAULT_CAPABILITY" to "a".repeat(43)), "/project", ":app", "dev", "debug") }
    }
    @Test fun `local broker endpoint passes validation before operating system gate`() {
        org.junit.jupiter.api.Assumptions.assumeFalse(System.getProperty("os.name").startsWith("Windows"))
        val target = com.lambdawalker.vault.protocol.BuildTarget("/project", ":app", "debug", "dev", "build")
        val invocation = com.lambdawalker.vault.protocol.BuildInvocation(target, "a".repeat(43), "\\\\.\\pipe\\lambdawalker-vault-00000000-0000-0000-0000-000000000000")
        val error = assertFailsWith<IllegalArgumentException> {
            BrokerClient.requestFrom(invocation.environment, "/project", ":app", "dev", "debug")
        }
        assertEquals("Vault signing requires Windows 11.", error.message)
    }
}
