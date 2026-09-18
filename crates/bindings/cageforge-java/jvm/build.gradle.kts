import org.gradle.api.tasks.bundling.Jar
import org.gradle.api.tasks.javadoc.Javadoc
import java.util.zip.ZipFile

plugins {
    `java-library`
    `maven-publish`
    signing
    checkstyle
    kotlin("jvm") version "2.1.20"
    id("org.jetbrains.dokka-javadoc") version "2.2.0"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.2"
}

group = providers.gradleProperty("mavenGroup").orElse("io.github.m62624").get()

fun workspaceVersion(manifest: File): String {
    val version =
        Regex("""(?ms)^\[workspace\.package\].*?^version\s*=\s*\"([^\"]+)\"""")
            .find(manifest.readText())
            ?.groupValues
            ?.get(1)
    return version ?: error("workspace package version is missing from ${manifest.path}")
}

val workspaceVersion = workspaceVersion(layout.projectDirectory.file("../../../../Cargo.toml").asFile)
version = providers.gradleProperty("releaseVersion").orElse(workspaceVersion).get()

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
    withSourcesJar()
    withJavadocJar()
}

kotlin { jvmToolchain(17) }

dependencies {
    api(kotlin("stdlib"))
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.12.2")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<Javadoc>().configureEach {
    // The public facade is implemented in Kotlin. Dokka supplies the
    // Java-facing documentation instead of the empty javac output.
    enabled = false
}

tasks.named<Jar>("javadocJar") {
    dependsOn("dokkaGeneratePublicationJavadoc")
    from(layout.buildDirectory.dir("dokka/javadoc"))
}

checkstyle {
    toolVersion = "10.21.2"
    configFile = layout.projectDirectory.file("config/checkstyle/checkstyle.xml").asFile
}

val nativeResources =
    providers.gradleProperty("nativeResourcesDir")
        .map { layout.projectDirectory.dir(it) }

val requiredNativeEntries =
    listOf(
        "META-INF/native/linux-x86_64/cageforge-linux-helper",
        "META-INF/native/linux-aarch64/cageforge-linux-helper",
        "META-INF/native/linux-x86_64/bwrap",
        "META-INF/native/linux-x86_64/bwrap.sha256",
        "META-INF/native/linux-aarch64/bwrap",
        "META-INF/native/linux-aarch64/bwrap.sha256",
        "META-INF/native/macos-x86_64/cageforge-macos-helper",
        "META-INF/native/macos-aarch64/cageforge-macos-helper",
        "META-INF/native/windows-x86_64/cageforge-windows-setup.exe",
        "META-INF/native/windows-aarch64/cageforge-windows-setup.exe",
        "META-INF/native/windows-x86_64/cageforge-windows-command-runner.exe",
        "META-INF/native/windows-aarch64/cageforge-windows-command-runner.exe",
        "META-INF/native/linux-x86_64/libcageforge_java.so",
        "META-INF/native/linux-aarch64/libcageforge_java.so",
        "META-INF/native/macos-x86_64/libcageforge_java.dylib",
        "META-INF/native/macos-aarch64/libcageforge_java.dylib",
        "META-INF/native/windows-x86_64/cageforge_java.dll",
        "META-INF/native/windows-aarch64/cageforge_java.dll",
    )

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.FAIL
    manifest {
        attributes["Implementation-Version"] = project.version.toString()
    }
    nativeResources.orNull?.let { from(it) }
    from(layout.projectDirectory.file("../../../../LICENSE")) { into("META-INF") }
    from(layout.projectDirectory.file("../../../../NOTICE")) { into("META-INF") }
    from(layout.projectDirectory.file("../../../../THIRD_PARTY_NOTICES.md")) { into("META-INF") }
    from(layout.projectDirectory.file("../README.md")) { into("META-INF") }
    from(layout.projectDirectory.file("../../../../crates/cageforge-bwrap/licenses/bubblewrap-COPYING")) {
        into("META-INF/licenses")
    }
}

val mavenRepositoryUrl = providers.gradleProperty("mavenRepositoryUrl")
val mavenSigningKey =
    providers.gradleProperty("signingKey")
        .orElse(providers.environmentVariable("MAVEN_GPG_PRIVATE_KEY"))
val mavenSigningPassword =
    providers.gradleProperty("signingPassword")
        .orElse(providers.environmentVariable("MAVEN_GPG_PASSPHRASE"))

tasks.register("verifyNativeBundle") {
    group = "verification"
    description = "Checks that all six JVM native target layouts and helpers are present."
    doLast {
        val directory =
            nativeResources.orNull
                ?: error("Pass -PnativeResourcesDir=<directory> to verify the release bundle")
        requiredNativeEntries.forEach { relative ->
            if (!directory.file(relative).asFile.isFile) error("Missing native bundle entry: $relative")
        }
    }
}

tasks.register("verifyMavenPublication") {
    group = "verification"
    description = "Checks the complete Maven publication and its native bundle."
    dependsOn(
        "verifyNativeBundle",
        "jar",
        "sourcesJar",
        "javadocJar",
        "generatePomFileForMavenJavaPublication",
        "generateMetadataFileForMavenJavaPublication",
    )
    doLast {
        val version = project.version.toString()
        val publicationDirectory = layout.buildDirectory.dir("publications/mavenJava").get().asFile
        val requiredFiles =
            listOf(
                layout.buildDirectory.file("libs/${project.name}-$version.jar").get().asFile,
                layout.buildDirectory.file("libs/${project.name}-$version-sources.jar").get().asFile,
                layout.buildDirectory.file("libs/${project.name}-$version-javadoc.jar").get().asFile,
                publicationDirectory.resolve("pom-default.xml"),
                publicationDirectory.resolve("module.json"),
            )
        requiredFiles.forEach { file ->
            check(file.isFile) { "Missing Maven publication file: ${file.path}" }
        }
        val jar = requiredFiles.first()
        ZipFile(jar).use { archive ->
            requiredNativeEntries.forEach { entry ->
                check(archive.getEntry(entry) != null) {
                    "Maven JAR is missing native entry: $entry"
                }
            }
            listOf(
                "META-INF/LICENSE",
                "META-INF/NOTICE",
                "META-INF/THIRD_PARTY_NOTICES.md",
                "META-INF/README.md",
                "META-INF/licenses/bubblewrap-COPYING",
            ).forEach { entry ->
                check(archive.getEntry(entry) != null) {
                    "Maven JAR is missing license entry: $entry"
                }
            }
        }
        val pom = publicationDirectory.resolve("pom-default.xml").readText()
        check("<groupId>${project.group}</groupId>" in pom) {
            "Maven POM groupId does not match ${project.group}"
        }
        check("<artifactId>${project.name}</artifactId>" in pom) {
            "Maven POM artifactId does not match ${project.name}"
        }
        check("<version>$version</version>" in pom) {
            "Maven POM version does not match $version"
        }
    }
}

publishing {
    repositories {
        if (mavenRepositoryUrl.isPresent) {
            maven {
                name = "centralPortal"
                url = uri(mavenRepositoryUrl.get())
                credentials {
                    username = providers.gradleProperty("mavenUsername").orNull
                        ?: System.getenv("MAVEN_USERNAME")
                    password = providers.gradleProperty("mavenPassword").orNull
                        ?: System.getenv("MAVEN_PASSWORD")
                }
            }
        }
    }
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            pom {
                name.set("Cageforge Java")
                description.set("JVM binding for the Cageforge cross-platform native sandbox")
                url.set("https://github.com/m62624/cageforge")
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                    license {
                        name.set("GNU Lesser General Public License, Version 2.1 or later")
                        url.set("https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/m62624/cageforge.git")
                    developerConnection.set("scm:git:ssh://github.com/m62624/cageforge.git")
                    url.set("https://github.com/m62624/cageforge")
                }
                developers {
                    developer {
                        id.set("m62624")
                        name.set("Mansur Azatbek")
                        email.set("mansur62624@gmail.com")
                    }
                }
            }
        }
    }
}

signing {
    if (mavenSigningKey.isPresent) {
        useInMemoryPgpKeys(mavenSigningKey.get(), mavenSigningPassword.orNull)
        sign(publishing.publications["mavenJava"])
    }
}

tasks.register("verifyMavenSigning") {
    group = "verification"
    description = "Checks that the Maven publication has the required PGP signing credentials."
    doLast {
        check(mavenSigningKey.isPresent) {
            "MAVEN_GPG_PRIVATE_KEY (or -PsigningKey) is required for Maven Central publication"
        }
        check(mavenSigningPassword.isPresent) {
            "MAVEN_GPG_PASSPHRASE (or -PsigningPassword) is required for Maven Central publication"
        }
    }
}

tasks.withType<PublishToMavenRepository>().configureEach {
    dependsOn("verifyMavenPublication")
    dependsOn("verifyMavenSigning")
    onlyIf { providers.gradleProperty("allowMavenPublish").isPresent }
}
