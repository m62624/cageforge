// SPDX-License-Identifier: Apache-2.0

use jni::errors::ErrorPolicy;
use jni::objects::JClass;
use jni::{Env, EnvUnowned};

/// Stable exception categories exposed by the JVM binding.
#[derive(Clone, Copy, Debug)]
pub(crate) enum BindingErrorKind {
    Internal,
    Configuration,
    Initialization,
    Launch,
    Permission,
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
pub(crate) struct BindingError {
    pub(crate) kind: BindingErrorKind,
    message: String,
}

impl BindingError {
    pub(crate) fn new(kind: BindingErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
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
            let message = jni::strings::JNIString::new(error.to_string());
            let _ = env.throw_new(class, message);
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
