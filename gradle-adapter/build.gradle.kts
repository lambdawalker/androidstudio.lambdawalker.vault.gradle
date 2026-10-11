plugins { kotlin("jvm"); `java-gradle-plugin`; `maven-publish` }
kotlin { jvmToolchain(25); compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
dependencies {
    implementation(project(":broker-protocol"))
    compileOnly("com.android.tools.build:gradle:9.4.0")
    testImplementation(gradleTestKit())
    testImplementation("net.java.dev.jna:jna-platform:5.19.1")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
gradlePlugin { plugins { create("vaultSigning") {
    id = "com.lambdawalker.vault.signing"
    implementationClass = "com.lambdawalker.vault.gradle.VaultSigningPlugin"
} } }
tasks.test { useJUnitPlatform() }
