plugins {
    `java-library`
    `maven-publish`
    checkstyle
    kotlin("jvm") version "2.1.20"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.2"
}

group = providers.gradleProperty("mavenGroup").orElse("ai.cageforge").get()
version = providers.gradleProperty("releaseVersion").orElse("0.2.0").get()

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

checkstyle {
    toolVersion = "10.21.2"
    configFile = layout.projectDirectory.file("config/checkstyle/checkstyle.xml").asFile
}

val nativeResources = providers.gradleProperty("nativeResourcesDir")
    .map { layout.projectDirectory.dir(it) }

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.FAIL
    manifest {
        attributes["Implementation-Version"] = project.version.toString()
    }
    nativeResources.orNull?.let { from(it) }
    from(layout.projectDirectory.file("../../../../LICENSE")) { into("META-INF") }
    from(layout.projectDirectory.file("../../../../NOTICE")) { into("META-INF") }
    from(layout.projectDirectory.file("../../../../THIRD_PARTY_NOTICES.md")) { into("META-INF") }
    from(layout.projectDirectory.file("../../../../crates/cageforge-bwrap/licenses/bubblewrap-COPYING")) {
        into("META-INF/licenses")
    }
}

val mavenRepositoryUrl = providers.gradleProperty("mavenRepositoryUrl")

tasks.register("verifyNativeBundle") {
    group = "verification"
    description = "Checks that all six JVM native target layouts and helpers are present."
    doLast {
        val directory = nativeResources.orNull
            ?: error("Pass -PnativeResourcesDir=<directory> to verify the release bundle")
        val required = listOf(
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
        required.forEach { relative ->
            if (!directory.file(relative).asFile.isFile) error("Missing native bundle entry: $relative")
        }
    }
}

publishing {
    repositories {
        if (mavenRepositoryUrl.isPresent) {
            maven {
                name = "manual"
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
                        name.set("GNU Lesser General Public License, Version 2.0 or later")
                        url.set("https://www.gnu.org/licenses/old-licenses/lgpl-2.0.html")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/m62624/cageforge.git")
                    developerConnection.set("scm:git:ssh://github.com/m62624/cageforge.git")
                    url.set("https://github.com/m62624/cageforge")
                }
                developers {
                    developer { name.set("Cageforge maintainers") }
                }
            }
        }
    }
}

tasks.withType<PublishToMavenRepository>().configureEach {
    dependsOn("verifyNativeBundle")
    onlyIf { providers.gradleProperty("allowMavenPublish").isPresent }
}
