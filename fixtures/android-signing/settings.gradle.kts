pluginManagement {
    includeBuild("../..")
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "vault-signing-fixture"
include(":app")
