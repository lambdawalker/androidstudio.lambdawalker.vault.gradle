// Test-only reference broker copied from Studio protocol v1.
package com.lambdawalker.vault.protocol

import java.util.Base64
import java.util.concurrent.TimeUnit


class GrantRegistry(private val clock: () -> Long = System::nanoTime) : AutoCloseable {
    private class Grant(val target: BuildTarget, val identity: SigningIdentity, val issued: Long)
    private val grants = mutableMapOf<String, Grant>()
    @Synchronized fun issue(target: BuildTarget, identity: SigningIdentity): String {
        require(identity.id == target.identity)
        expire()
        require(grants.size < 8) { "Too many pending builds." }
        val capability = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also(java.security.SecureRandom()::nextBytes))
        grants[capability] = Grant(target, identity, clock())
        return capability
    }
    @Synchronized fun redeem(capability: String, target: BuildTarget): SigningIdentity {
        val grant = grants.remove(capability) ?: error("Build authorization is unavailable.")
        if (clock() - grant.issued >= TimeUnit.SECONDS.toNanos(60) || grant.target != target) {
            grant.identity.close(); error("Build authorization expired or target changed. Authorize a new build.")
        }
        return grant.identity
    }
    @Synchronized fun revokeAll() { grants.values.forEach { it.identity.close() }; grants.clear() }
    @Synchronized fun revoke(buildId: String) {
        grants.entries.filter { it.value.target.buildId == buildId }.forEach { (_, grant) -> grant.identity.close() }
        grants.entries.removeIf { it.value.target.buildId == buildId }
    }
    private fun expire() {
        grants.entries.removeIf { (_, grant) ->
            (clock() - grant.issued >= TimeUnit.SECONDS.toNanos(60)).also { if (it) grant.identity.close() }
        }
    }
    override fun close() = revokeAll()
}

class PinThrottle(private val clock: () -> Long = System::nanoTime) {
    private var failures = 0
    private var deadline = clock()
    @Synchronized fun failed() {
        failures = (failures + 1).coerceAtMost(9)
        if (failures >= 5) deadline = clock() + TimeUnit.SECONDS.toNanos((30L shl (failures - 5)).coerceAtMost(300))
    }
    @Synchronized fun remainingSeconds(): Long = ((deadline - clock()).coerceAtLeast(0) + 999_999_999) / 1_000_000_000
    @Synchronized fun reset() { failures = 0; deadline = clock() }
}
