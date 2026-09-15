# Specification 0020: Cageforge JVM Binding

Status: draft; implementation in progress

## Purpose and package boundary

The JVM binding exposes Cageforge's launch and security contract to Java and
Kotlin/JVM desktop applications on Linux, macOS, and Windows. Android and
Kotlin/Native are outside this specification.

The workspace package `cageforge-java` is an independently authored internal
JNI implementation and must keep `publish = false`. It depends on the public
`cageforge` facade, not directly on platform backend crates. The public
distribution is a JVM artifact named `cageforge-java`; Maven consumers never
need the internal Cargo package.

The binding is not a harness- or product-specific protocol. It is a general-
purpose adapter over the existing Cageforge facade and may be used by desktop
applications, agent hosts, build tools, and plugin hosts.

## Native bridge and distribution

The Rust implementation is a `cdylib` with a narrow JNI surface. It stores
opaque runtime and child handles and delegates configuration parsing, policy
composition, backend preparation, native launch, process-tree termination,
and typed native failures to `cageforge`.

The public Maven artifact contains the JNI library and the helper resources for
each supported target:

```text
META-INF/native/linux-x86_64/
META-INF/native/linux-aarch64/
META-INF/native/macos-x86_64/
META-INF/native/macos-aarch64/
META-INF/native/windows-x86_64/
META-INF/native/windows-aarch64/
```

Each target directory contains its JNI library and the helper binaries needed
by that native backend. Linux target directories additionally contain
Cageforge's reviewed `bwrap` executable and its `bwrap.sha256` manifest. The
native configuration keeps the `system-then-bundled` selection behavior: a
compatible system Bubblewrap is preferred and the verified JAR resource is the
fallback. A JVM loader selects the host OS and architecture,
extracts the selected resources into a versioned cache, verifies cached bytes
before reuse, marks POSIX helpers executable, and calls `System.load` on the
selected JNI library. The loader passes the resulting absolute resource
directory to Rust. `current_exe()` must never be used as a helper path from the
JVM binding because it identifies `java`/`javaw`, not a Cageforge helper.

The artifact is published as the Maven coordinate
`io.github.m62624:cageforge-java:<version>` with sources, Javadoc,
POM, module metadata, and Apache-2.0/LGPL-2.0-or-later license metadata.
Native variants are implementation resources of one versioned artifact rather
than separate consumer dependencies. Release CI builds every target, assembles
the single artifact, and verifies that all required resources are present.
Maven publication is an explicit release operation. The current release path
uses Central Portal token credentials and PGP signing; a later trusted/OIDC
publishing path may replace the token authentication without changing the
artifact coordinates or native bundle contract.

## Configuration and public surface

The JVM API intentionally does not mirror every Rust model or expose native
backend structs. Detailed policy remains in the validated Cageforge TOML
format, including profile inheritance, filesystem rules, network rules,
environment transformations, workspace-root declarations, commands, and
timeouts.

The thin public surface covers every launch and security operation needed by a
host:

- `Cageforge.fromToml` and `Cageforge.fromTomlFile` select a profile and
  create one reusable native runtime;
- `RuntimeContext` supplies the absolute current directory used to resolve
  relative workspace declarations and platform runtime paths;
- `Cageforge.launch(argv)` passes an explicit, NUL-validated argv vector or
  launches the command declared by the profile;
- `SandboxProcess` exposes the process identifier, TOML-selected standard
  stream pipes, non-blocking status, bounded lifecycle operations, wait,
  asynchronous wait, termination, and close; and
  - `WindowsSetup.install`/`status`/`verify`/`uninstall` expose explicit
     owner-scoped setup lifecycle and read-back operations. Installation retains
     the native Windows `runas`/UAC behavior and does not silently provision the
     machine during runtime creation. `WindowsSetup.isSupported()` provides a
     family-level Windows check without requiring a list of Windows releases.
     The methods are linkable from every JVM target but fail with a typed
     `UnsupportedPlatformException` before native loading on non-Windows hosts.

The binding must keep these invariants from the Rust facade:

1. TOML is parsed and resolved by `cageforge-config`; Java strings are not a
   second policy language.
2. Relative workspace declarations are resolved against the supplied absolute
   current directory with lexical parent traversal rejected. The runtime
   context is explicit and never inferred from filesystem discovery.
3. Profile policy and environment are composed through `PolicyCeiling` and
   `compose` before the backend receives a request; the resolved profile
   gateway limits are passed unchanged into the selected native backend.
4. Commands use argv values and do not implicitly invoke a shell.
5. The resolved command `StdioSpec` is preserved. JVM stream properties are
   present only for `pipe` streams; `inherit` and `null` remain native routing
   choices and are not silently converted to captured pipes.
6. Native backend feature selection is exact per target OS. The binding does
   not enable or load another OS backend on the host.
7. Windows setup is explicit, verified, owner-scoped, and may require UAC.
   Constructing a runtime only verifies an existing setup; it does not install
   global Windows objects implicitly.
8. JNI handles are opaque, validated for zero/closed state, reclaimed exactly
   once, and never allow a Rust panic to cross the JNI boundary.
9. Native errors become Java exceptions with the original diagnostic text;
   Rust model types and native backend internals do not cross the ABI.

The binding exports all security controls present in the Cageforge TOML and
native facade, including process-tree lifecycle, filesystem ownership and
path rules, network modes/domain/socket authorization, gateway bounds,
environment filtering, stdio routing, timeouts, workspace ceilings, and
platform-specific native enforcement. Cageforge does not currently expose a
portable RAM/CPU/process-count quota; memory and IPC namespace isolation are
native enforcement behavior, not configurable memory quotas.

## Concurrency and lifecycle contract

JNI native methods are not declared `synchronized` and the binding must not
introduce a static/global Java execution monitor, a JVM-wide Rust mutex, or a
GIL-equivalent serialization point. The loader may use a short one-time lock
for resource extraction and `System.load`; that lock is released before
runtime creation and never surrounds launch, wait, stream, or kill operations.
Runtime synchronization is per opaque runtime handle, and child
synchronization is per opaque process handle. Operations on independent
runtimes/processes must be able to proceed concurrently; internal Cageforge
backend mutexes, semaphores, timeout state, network registries, and helper
threads remain scoped to backend behavior and must not be exposed as a Java
global execution lock.

The JVM facade holds the corresponding per-object lifecycle lock across a
native operation so `close` cannot reclaim a raw JNI handle concurrently. This
does not serialize independent handles. Same-child `kill` can therefore wait
for an already-running blocking `waitFor` or stream read; the asynchronous wait
API is the way to keep the caller thread responsive.

The synchronous `waitFor` and stream reads are explicitly blocking. They must
not be called on Swing/JavaFX event-dispatch threads when UI responsiveness is
required. The JVM facade provides `waitForAsync(Executor)` so the blocking
native wait runs on an application-selected worker. `tryWait` remains the
non-blocking status query. Stream consumers should use worker threads or a
coroutine dispatcher because an `InputStream.read` can wait for child output.

The binding must test concurrent independent launches, no cross-runtime lock
contention, closed-handle rejection, repeated close, and the documented
wait/kill lifecycle. A blocking operation on one child must not acquire a
global lock or prevent unrelated child handles from progressing. If the
underlying native child API serializes operations on one child, that fact must
remain explicit in the Java lifecycle documentation and tests must ensure the
application can still use `waitForAsync` without blocking its caller thread.

## Validation and CI

The JVM project uses Java 17 as its baseline, Kotlin/JVM compilation, JUnit
tests in both Java and Kotlin source sets, Checkstyle for Java, and ktlint for
Kotlin. CI runs the JVM checks on Linux, macOS, and Windows, and compiles the
matching Rust JNI feature on each runner. The existing native backend jobs
remain authoritative for Linux, macOS, and Windows enforcement behavior. The
JVM matrix is a final consumer stage and starts only after all selected Rust
component, native-backend, and Rust CLI cross-build jobs have completed
successfully; skipped lanes for an unrelated narrow PR do not block it.
The change classifier schedules this final stage for the binding, its Rust
facade/backend dependencies, workspace/toolchain/CI changes, main pushes, and
full release validation; unrelated crate-only or documentation-only PRs can
skip the JVM stage.

Each JVM matrix job additionally assembles a local JAR from the just-built JNI
library and platform helper assets, connects that JAR to a separate minimal
Java consumer project, and runs a real restricted command on its OS. The Linux
matrix job packages its consumer distribution, and a separate Java-only QEMU
job runs that exact distribution inside the same disposable Ubuntu guest model
used by `ci/run-native-linux-vm.sh`. This keeps Bubblewrap user-namespace
behavior out of the GitHub host runner, whose AppArmor policy is not the
supported Cageforge execution environment. The consumer must print the
selected target and a successful action marker. The Windows consumer also
exercises the explicit setup/UAC lifecycle. This checks resource selection,
extraction, JNI loading, TOML runtime creation, and native process execution
together rather than testing only compiled classes.

The Linux VM launcher is suite-oriented rather than binding-oriented. A suite
under `ci/vm-suites/<name>/` declares its guest packages and the
`bootstrap.sh`, `prepare.sh`, and `run.sh` phases. External build outputs are
passed as named read-only payload archives. Adding another FFI consumer check
therefore adds a suite and a payload declaration without adding language-
specific branches to the QEMU lifecycle or Bubblewrap setup.

The release workflow keeps Cargo trusted publishing unchanged: `publish =
false` causes the internal binding package to be skipped by `cargo publish
--workspace`. A separate JVM artifact assembly step follows the same tested
release tag and version but does not publish to Maven until explicit release
credentials are configured. Publication must run the full Gradle verification
and inspect the generated POM, sources, Javadoc, license, PGP signatures, and
all native resources.

### Maven Central release credential contract

The public artifact uses the coordinate
`io.github.m62624:cageforge-java:<version>`. The release workflow reads the
following repository configuration from GitHub Actions:

- repository variable `MAVEN_CENTRAL_NAMESPACE` set to `io.github.m62624`;
- repository secret `MAVEN_CENTRAL_USERNAME` containing the `<username>` value
  from a Central Portal user token;
- repository secret `MAVEN_CENTRAL_PASSWORD` containing the `<password>` value
  from that token;
- repository secret `MAVEN_GPG_PRIVATE_KEY` containing the complete
  ASCII-armored private OpenPGP signing key; and
- repository secret `MAVEN_GPG_PASSPHRASE` containing the passphrase for that
  private key.

The Maven `settings.xml` example's `<id>${server}</id>` is only a local
repository alias and is not a GitHub secret. The public key corresponding to
`MAVEN_GPG_PRIVATE_KEY` must be published to a Central-supported OpenPGP
keyserver. The Gradle release job loads the private key in memory, creates the
detached publication signatures, uploads through the Central Portal OSSRH
Staging API using the token credentials, and promotes the completed deployment
with the namespace endpoint. The internal Cargo binding remains
`publish = false`; Cargo trusted publishing is independent of this JVM
publication path.

## Relationship to existing specifications

The binding consumes the facade, command, configuration, policy-composition,
backend API, and native backend contracts from Specifications 0008-0019. It
does not duplicate their path parser or platform policy logic. Platform
resource naming and helper behavior remain owned by the corresponding native
backend specifications; this document only defines how the JVM package locates
and passes those resources to the existing APIs.
