package com.lambdawalker.vault.gradle

import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import org.gradle.api.*
import org.gradle.api.provider.Property

abstract class VaultSigningExtension {
    abstract val identity: Property<String>
    abstract val variant: Property<String>
}

class VaultSigningPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val binding = project.extensions.create("vaultSigning", VaultSigningExtension::class.java)
        project.plugins.withId("com.android.application") {
            val components = project.extensions.getByType(ApplicationAndroidComponentsExtension::class.java)
            val environment = System.getenv()
            val authorized = environment["LW_VAULT_MODULE"] == project.path
            if (authorized) {
                check(components.pluginVersion.toString() == "9.4.0") { "Signing Vault requires tested AGP 9.4.0." }
                check(!project.gradle.startParameter.isBuildCacheEnabled && !project.gradle.startParameter.isConfigurationCacheRequested) { "Vault builds must disable build and configuration caches." }
                project.rootProject.plugins.withId("com.gradle.develocity") { error("Build scans are unsupported for vault builds.") }
                project.rootProject.plugins.withId("com.gradle.enterprise") { error("Build scans are unsupported for vault builds.") }
            }
            components.finalizeDsl { android ->
                val identity = binding.identity.get()
                val variant = binding.variant.get()
                require(variant.matches(Regex("[A-Za-z][A-Za-z0-9]*"))) { "Invalid vault variant." }
                val buildType = android.buildTypes.singleOrNull { variant == it.name || variant.endsWith(it.name.replaceFirstChar(Char::uppercaseChar)) }
                    ?: error("Vault variant does not identify exactly one build type.")
                // Prevent Android's implicit debug key from being substituted while locked.
                buildType.signingConfig = null
                if (authorized) {
                    val task = "${project.path}:assemble${variant.replaceFirstChar(Char::uppercaseChar)}"
                    check(project.gradle.startParameter.taskNames == listOf(task)) { "Vault builds must target the single authorized assemble task." }
                    val material = BrokerClient.requestFrom(environment, project.rootDir.canonicalPath, project.path, identity, variant)
                        ?: error("Build authorization is missing.")
                    material.use {
                        val signing = android.signingConfigs.create("lambdawalkerVault")
                        signing.storeFile = project.file(it.path)
                        signing.storeType = it.storeType
                        signing.keyAlias = it.alias
                        signing.storePassword = String(it.storePassword)
                        signing.keyPassword = String(it.keyPassword)
                        buildType.signingConfig = signing
                    }
                }
            }
            if (authorized) components.beforeVariants(components.selector().all()) { builder ->
                if (builder.name != binding.variant.get()) builder.enable = false
            }
        }
    }
}
