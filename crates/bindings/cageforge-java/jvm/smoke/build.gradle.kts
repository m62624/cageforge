plugins {
    application
}

group = "ai.cageforge.smoke"
version = "0.0.0"

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
}

fun workspaceVersion(manifest: File): String {
    val version =
        Regex("""(?ms)^\[workspace\.package\].*?^version\s*=\s*\"([^\"]+)\"""")
            .find(manifest.readText())
            ?.groupValues
            ?.get(1)
    return version ?: error("workspace package version is missing from ${manifest.path}")
}

val bindingVersion =
    providers.gradleProperty("bindingVersion")
        .orElse(workspaceVersion(file("../../../../../Cargo.toml")))

dependencies {
    implementation(files("../build/libs/cageforge-java-${bindingVersion.get()}.jar"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.1.20")
}

application {
    mainClass.set("ai.cageforge.smoke.Main")
    applicationDefaultJvmArgs = providers.gradleProperty("nativeCache")
        .map { listOf("-Dcageforge.native.cache=$it") }
        .orElse(emptyList())
        .get()
}
