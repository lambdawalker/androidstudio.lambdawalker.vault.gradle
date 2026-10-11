pluginManagement { repositories { gradlePluginPortal(); mavenCentral(); google() } }
dependencyResolutionManagement { repositories { mavenCentral(); google() } }
rootProject.name = "signing-vault-gradle"
include(":broker-protocol", ":gradle-adapter")
