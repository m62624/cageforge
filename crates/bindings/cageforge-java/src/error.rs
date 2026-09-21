// SPDX-License-Identifier: Apache-2.0

use jni::errors::ErrorPolicy;
use jni::objects::{JClass, JObject, JThrowable, JValue};
use jni::{Env, EnvUnowned};

/// Stable exception categories exposed by the JVM binding.
#[derive(Clone, Copy, Debug)]
pub(crate) enum BindingErrorKind {
    Internal,
    Configuration,
    Initialization,
    Launch,
    Permission,
    Escalation,
    PermissionStore,
    StorePath,
    GrantNotFound,
    ListingSnapshotExpired,
    InvalidGrantId,
    InvalidCursor,
    InvalidPageSize,
    StoreLocked,
    StoreRead,
    StoreWrite,
    StoreFormat,
    Process,
    Stream,
    WindowsSetup,
}

impl BindingErrorKind {
    fn class<'local>(self, env: &mut Env<'local>) -> jni::errors::Result<JClass<'local>> {
        match self {
            Self::Internal => env.find_class(jni::jni_str!("ai/cageforge/CageforgeException")),
            Self::Configuration => env.find_class(jni::jni_str!(
                "ai/cageforge/CageforgeConfigurationException"
            )),
            Self::Initialization => env.find_class(jni::jni_str!(
                "ai/cageforge/CageforgeInitializationException"
            )),
            Self::Launch => env.find_class(jni::jni_str!("ai/cageforge/CageforgeLaunchException")),
            Self::Permission => {
                env.find_class(jni::jni_str!("ai/cageforge/CageforgePermissionException"))
            }
            Self::Escalation => {
                env.find_class(jni::jni_str!("ai/cageforge/CageforgeEscalationException"))
            }
            Self::PermissionStore => env.find_class(jni::jni_str!(
                "ai/cageforge/CageforgePermissionStoreException"
            )),
            Self::StorePath => {
                env.find_class(jni::jni_str!("ai/cageforge/CageforgeStorePathException"))
            }
            Self::GrantNotFound => env.find_class(jni::jni_str!(
                "ai/cageforge/CageforgeGrantNotFoundException"
            )),
            Self::ListingSnapshotExpired => env.find_class(jni::jni_str!(
                "ai/cageforge/CageforgeListingSnapshotExpiredException"
            )),
            Self::InvalidGrantId => env.find_class(jni::jni_str!(
                "ai/cageforge/CageforgeInvalidGrantIdException"
            )),
            Self::InvalidCursor => env.find_class(jni::jni_str!(
                "ai/cageforge/CageforgeInvalidCursorException"
            )),
            Self::InvalidPageSize => env.find_class(jni::jni_str!(
                "ai/cageforge/CageforgeInvalidPageSizeException"
            )),
            Self::StoreLocked => {
                env.find_class(jni::jni_str!("ai/cageforge/CageforgeStoreLockedException"))
            }
            Self::StoreRead => {
                env.find_class(jni::jni_str!("ai/cageforge/CageforgeStoreReadException"))
            }
            Self::StoreWrite => {
                env.find_class(jni::jni_str!("ai/cageforge/CageforgeStoreWriteException"))
            }
            Self::StoreFormat => {
                env.find_class(jni::jni_str!("ai/cageforge/CageforgeStoreFormatException"))
            }
            Self::Process => {
                env.find_class(jni::jni_str!("ai/cageforge/CageforgeProcessException"))
            }
            Self::Stream => env.find_class(jni::jni_str!("ai/cageforge/CageforgeStreamException")),
            Self::WindowsSetup => {
                env.find_class(jni::jni_str!("ai/cageforge/CageforgeWindowsSetupException"))
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct BindingDiagnostic {
    pub(crate) code: String,
    pub(crate) config_path: Option<String>,
    pub(crate) profile: Option<String>,
    pub(crate) platform: Option<String>,
    pub(crate) field: Option<String>,
    pub(crate) command: Option<String>,
    pub(crate) line: Option<i32>,
    pub(crate) column: Option<i32>,
}

impl BindingDiagnostic {
    pub(crate) fn from_config(error: &cageforge::ConfigError) -> Self {
        let diagnostic = error.diagnostic();
        let location = diagnostic.location();
        Self {
            code: diagnostic.code().to_owned(),
            config_path: diagnostic
                .config_path()
                .map(|path| path.display().to_string()),
            profile: diagnostic.profile().map(str::to_owned),
            platform: diagnostic
                .platform()
                .map(|platform| platform.as_str().to_owned()),
            field: diagnostic.field().map(str::to_owned),
            command: diagnostic.command().map(str::to_owned),
            line: location.and_then(|value| i32::try_from(value.line).ok()),
            column: location.and_then(|value| i32::try_from(value.column).ok()),
        }
    }

    pub(crate) fn from_runtime(
        source: &cageforge::ProfileSourceContext,
        command: &cageforge::CommandRequest,
        error: &(dyn std::error::Error + 'static),
    ) -> (Self, String) {
        let command = display_command(command);
        let diagnostic =
            cageforge::config_diagnostic_for_runtime_failure(source, Some(&command), error);
        let location = diagnostic.location();
        (
            Self {
                code: diagnostic.code().to_owned(),
                config_path: diagnostic
                    .config_path()
                    .map(|path| path.display().to_string()),
                profile: diagnostic.profile().map(str::to_owned),
                platform: diagnostic
                    .platform()
                    .map(|platform| platform.as_str().to_owned()),
                field: diagnostic.field().map(str::to_owned),
                command: diagnostic.command().map(str::to_owned),
                line: location.and_then(|value| i32::try_from(value.line).ok()),
                column: location.and_then(|value| i32::try_from(value.column).ok()),
            },
            diagnostic.render_human(),
        )
    }
}

fn display_command(command: &cageforge::CommandRequest) -> String {
    std::iter::once(command.command().program())
        .chain(
            command
                .command()
                .args()
                .iter()
                .map(std::ffi::OsString::as_os_str),
        )
        .map(|part| part.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug)]
pub(crate) struct BindingError {
    pub(crate) kind: BindingErrorKind,
    message: String,
    diagnostic: Option<Box<BindingDiagnostic>>,
}

impl BindingError {
    pub(crate) fn new(kind: BindingErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            diagnostic: None,
        }
    }

    pub(crate) fn configuration(error: cageforge::ConfigError) -> Self {
        let diagnostic = error.diagnostic();
        Self {
            kind: BindingErrorKind::Configuration,
            message: diagnostic.render_human(),
            diagnostic: Some(Box::new(BindingDiagnostic::from_config(&error))),
        }
    }

    pub(crate) fn runtime(
        kind: BindingErrorKind,
        source: &cageforge::ProfileSourceContext,
        command: &cageforge::CommandRequest,
        error: &(dyn std::error::Error + 'static),
    ) -> Self {
        let (diagnostic, rendered) = BindingDiagnostic::from_runtime(source, command, error);
        Self {
            message: rendered,
            kind,
            diagnostic: Some(Box::new(diagnostic)),
        }
    }

    pub(crate) fn with_default_kind(mut self, kind: BindingErrorKind) -> Self {
        if matches!(self.kind, BindingErrorKind::Internal) {
            self.kind = kind;
        }
        self
    }
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BindingError {}

impl From<String> for BindingError {
    fn from(message: String) -> Self {
        Self {
            kind: BindingErrorKind::Internal,
            message,
            diagnostic: None,
        }
    }
}

impl From<BindingError> for String {
    fn from(error: BindingError) -> Self {
        error.message
    }
}

impl From<jni::errors::Error> for BindingError {
    fn from(error: jni::errors::Error) -> Self {
        Self::from(error.to_string())
    }
}

fn throw_diagnostic_exception(
    env: &mut Env<'_>,
    class: &JClass<'_>,
    message: &str,
    diagnostic: &BindingDiagnostic,
) -> jni::errors::Result<()> {
    let message = env.new_string(message)?;
    let code = env.new_string(&diagnostic.code)?;
    let config_path = diagnostic
        .config_path
        .as_deref()
        .map(|value| env.new_string(value))
        .transpose()?;
    let profile = diagnostic
        .profile
        .as_deref()
        .map(|value| env.new_string(value))
        .transpose()?;
    let platform = diagnostic
        .platform
        .as_deref()
        .map(|value| env.new_string(value))
        .transpose()?;
    let field = diagnostic
        .field
        .as_deref()
        .map(|value| env.new_string(value))
        .transpose()?;
    let command = diagnostic
        .command
        .as_deref()
        .map(|value| env.new_string(value))
        .transpose()?;
    let line = match diagnostic.line {
        Some(value) => env.new_object(
            jni::jni_str!("java/lang/Integer"),
            jni::jni_sig!("(I)V"),
            &[JValue::Int(value)],
        )?,
        None => JObject::null(),
    };
    let column = match diagnostic.column {
        Some(value) => env.new_object(
            jni::jni_str!("java/lang/Integer"),
            jni::jni_sig!("(I)V"),
            &[JValue::Int(value)],
        )?,
        None => JObject::null(),
    };
    let object = env.new_object(
        class,
        jni::jni_sig!("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;)V"),
        &[
            JValue::Object(message.as_ref()),
            JValue::Object(code.as_ref()),
            JValue::Object(config_path.as_ref().map_or(JObject::null().as_ref(), |value| value.as_ref())),
            JValue::Object(profile.as_ref().map_or(JObject::null().as_ref(), |value| value.as_ref())),
            JValue::Object(platform.as_ref().map_or(JObject::null().as_ref(), |value| value.as_ref())),
            JValue::Object(field.as_ref().map_or(JObject::null().as_ref(), |value| value.as_ref())),
            JValue::Object(&line),
            JValue::Object(&column),
            JValue::Object(command.as_ref().map_or(JObject::null().as_ref(), |value| value.as_ref())),
        ],
    )?;
    let throwable = unsafe { JThrowable::from_raw(env, object.into_raw()) };
    env.throw(throwable)
}

pub(crate) struct ThrowCageforgeException;

impl<T: Default> ErrorPolicy<T, BindingError> for ThrowCageforgeException {
    type Captures<'unowned_env_local: 'native_method, 'native_method> = ();

    fn on_error<'unowned_env_local: 'native_method, 'native_method>(
        env: &mut Env<'unowned_env_local>,
        _captures: &mut Self::Captures<'unowned_env_local, 'native_method>,
        error: BindingError,
    ) -> jni::errors::Result<T> {
        if !env.exception_check() {
            let class = error.kind.class(env)?;
            if let Some(diagnostic) = error.diagnostic.as_ref() {
                if throw_diagnostic_exception(env, &class, &error.message, diagnostic).is_err() {
                    let message = jni::strings::JNIString::new(error.to_string());
                    let _ = env.throw_new(class, message);
                }
            } else {
                let message = jni::strings::JNIString::new(error.to_string());
                let _ = env.throw_new(class, message);
            }
        }
        Ok(T::default())
    }

    fn on_panic<'unowned_env_local: 'native_method, 'native_method>(
        env: &mut Env<'unowned_env_local>,
        _captures: &mut Self::Captures<'unowned_env_local, 'native_method>,
        _payload: Box<dyn std::any::Any + Send + 'static>,
    ) -> jni::errors::Result<T> {
        if !env.exception_check() {
            let class = BindingErrorKind::Internal.class(env)?;
            let message = jni::strings::JNIString::new("Cageforge native binding panicked");
            let _ = env.throw_new(class, message);
        }
        Ok(T::default())
    }
}

pub(crate) fn ffi_call_kind<'local, T: Default>(
    env: &mut EnvUnowned<'local>,
    kind: BindingErrorKind,
    operation: impl FnOnce(&mut Env<'local>) -> Result<T, BindingError>,
) -> T {
    env.with_env(|env| operation(env).map_err(|error| error.with_default_kind(kind)))
        .resolve::<ThrowCageforgeException>()
}
