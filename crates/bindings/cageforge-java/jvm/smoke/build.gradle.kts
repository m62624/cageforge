plugins {
    application
}

group = "ai.cageforge.smoke"
version = "0.0.0"

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
}

val bindingVersion = providers.gradleProperty("bindingVersion").orElse("0.2.0")

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
