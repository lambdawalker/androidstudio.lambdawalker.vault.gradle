package com.lambdawalker.vault.protocol

class BuildInvocation(val target: BuildTarget, capability: String, endpoint: String) {
    init {
        require(target.module.matches(Regex("(:[A-Za-z0-9_-]+)+"))) { "Use a module path such as :app." }
        require(target.variant.matches(Regex("[A-Za-z][A-Za-z0-9]*"))) { "Invalid variant." }
    }
    val task = "${target.module}:assemble${target.variant.replaceFirstChar(Char::uppercaseChar)}"
    val arguments = listOf(task, "--no-daemon", "--no-configuration-cache", "--no-build-cache", "--no-scan", "--rerun-tasks", "--console=plain")
    val environment = mapOf("LW_VAULT_PIPE" to endpoint, "LW_VAULT_CAPABILITY" to capability,
        "LW_VAULT_PROJECT" to target.project, "LW_VAULT_MODULE" to target.module,
        "LW_VAULT_VARIANT" to target.variant, "LW_VAULT_IDENTITY" to target.identity, "LW_VAULT_BUILD" to target.buildId)
    override fun toString() = "BuildInvocation(redacted)"
}
