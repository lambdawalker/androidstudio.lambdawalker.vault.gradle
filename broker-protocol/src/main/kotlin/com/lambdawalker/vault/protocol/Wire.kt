package com.lambdawalker.vault.protocol

import java.io.*

class BuildProof(val capability: String, val target: BuildTarget) {
    override fun toString() = "BuildProof(redacted)"
}

/** Length-prefixed, bounded single-request protocol. Errors contain no remote diagnostic text. */
object Wire {
    fun writeRequest(output: DataOutputStream, capability: String, target: BuildTarget) {
        val data = binary {
            writeInt(1)
            listOf(capability, target.project, target.module, target.variant, target.identity, target.buildId).forEach { field(it.toByteArray(Charsets.UTF_8)) }
        }
        try { frame(output, data) } finally { data.fill(0) }
    }
    fun readRequest(input: DataInputStream): BuildProof {
        val data = readFrame(input)
        try {
            val stream = DataInputStream(ByteArrayInputStream(data))
            require(stream.readInt() == 1)
            val values = (0..5).map { val bytes = stream.field(); try { String(decodeSecret(bytes)) } finally { bytes.fill(0) } }
            require(stream.available() == 0 && values[0].matches(Regex("[A-Za-z0-9_-]{43}")))
            return BuildProof(values[0], BuildTarget(values[1], values[2], values[3], values[4], values[5]))
        } finally { data.fill(0) }
    }
    fun writeIdentity(output: DataOutputStream, identity: SigningIdentity) {
        val data = Payload.encode(listOf(identity))
        try { output.writeBoolean(true); frame(output, data) } finally { data.fill(0) }
    }
    fun writeFailure(output: DataOutputStream) { output.writeBoolean(false); output.flush() }
    fun readIdentity(input: DataInputStream): SigningIdentity {
        check(input.readBoolean()) { "Build authorization failed. Unlock and authorize a new build." }
        val data = readFrame(input)
        try {
            val identities = Payload.decode(data)
            if (identities.size != 1) { identities.forEach(SigningIdentity::close); error("Invalid broker response.") }
            return identities.single()
        } finally { data.fill(0) }
    }
    private fun frame(output: DataOutputStream, data: ByteArray) {
        require(data.size in 1..65536); output.writeInt(data.size); output.write(data); output.flush()
    }
    private fun readFrame(input: DataInputStream): ByteArray {
        val size = input.readInt(); require(size in 1..65536) { "Invalid broker frame." }
        return ByteArray(size).also(input::readFully)
    }
}
