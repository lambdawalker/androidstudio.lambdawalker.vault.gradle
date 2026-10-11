package com.lambdawalker.vault.protocol

import org.junit.jupiter.api.Test
import java.io.*
import kotlin.test.*

class WireTest {
    @Test fun `bounded protocol round trips target and signing material`() {
        val out = ByteArrayOutputStream()
        val target = BuildTarget("C:\\project", ":app", "debug", "dev", "build")
        Wire.writeRequest(DataOutputStream(out), "a".repeat(43), target)
        val request = Wire.readRequest(DataInputStream(ByteArrayInputStream(out.toByteArray())))
        assertEquals(target, request.target)
        assertEquals("a".repeat(43), request.capability)
    }
    @Test fun `oversized protocol frames are rejected before allocation`() {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).writeInt(65537)
        assertFails { Wire.readRequest(DataInputStream(ByteArrayInputStream(out.toByteArray()))) }
    }
    @Test fun `wire errors never include secret diagnostics`() {
        val out = ByteArrayOutputStream()
        Wire.writeFailure(DataOutputStream(out))
        assertFailsWith<IllegalStateException> { Wire.readIdentity(DataInputStream(ByteArrayInputStream(out.toByteArray()))) }
    }
}
