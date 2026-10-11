package com.lambdawalker.vault.protocol
import java.io.*
import org.junit.jupiter.api.Test
import kotlin.test.*
class ProtocolContractTest {
    private fun bytes(hex: String) = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    @Test fun `v1 request matches independent contract vector`() {
        val expected = bytes("00000064000000010000002b414141414141414141414141414141414141414141414141414141414141414141414141414141414141410000000a433a2f70726f6a656374000000043a61707000000005646562756700000003646576000000076275696c642d31")
        val output = ByteArrayOutputStream()
        Wire.writeRequest(DataOutputStream(output), "A".repeat(43), BuildTarget("C:/project", ":app", "debug", "dev", "build-1"))
        assertContentEquals(expected, output.toByteArray())
        val proof = Wire.readRequest(DataInputStream(ByteArrayInputStream(expected)))
        assertEquals("build-1", proof.target.buildId)
    }
    @Test fun `v1 identity matches independent contract vector`() {
        val expected = bytes("010000008c00000001000000036465760000000a433a2f6b65792e70313200000006504b435331320000000772656c6561736500000040616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161610000000a746573742d73746f726500000008746573742d6b6579")
        Wire.readIdentity(DataInputStream(ByteArrayInputStream(expected))).use { identity ->
            assertEquals("release", identity.alias)
            assertContentEquals("test-store".toCharArray(), identity.storePassword)
            assertContentEquals("test-key".toCharArray(), identity.keyPassword)
            val output = ByteArrayOutputStream()
            Wire.writeIdentity(DataOutputStream(output), identity)
            assertContentEquals(expected, output.toByteArray())
        }
    }
    @Test fun `unsupported version and oversized frames fail closed`() {
        val wrong = bytes("00000064000000010000002b414141414141414141414141414141414141414141414141414141414141414141414141414141414141410000000a433a2f70726f6a656374000000043a61707000000005646562756700000003646576000000076275696c642d31").also { it[7] = 2 }
        assertFails { Wire.readRequest(DataInputStream(ByteArrayInputStream(wrong))) }
        assertFails { Wire.readRequest(DataInputStream(ByteArrayInputStream(byteArrayOf(0, 1, 0, 1)))) }
    }
}
