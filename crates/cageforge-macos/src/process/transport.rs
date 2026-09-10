// SPDX-License-Identifier: Apache-2.0

//! Owned XPC transport primitives used by the launchd helper admission tests.
//! Requests move into the transport: a timeout cannot return mutable access to
//! a dictionary that XPC may still be sending on another thread.

#![allow(unsafe_code)]

use block2::{Block, RcBlock};
use std::{
    ffi::{CStr, c_void},
    fs::File,
    io,
    os::fd::{FromRawFd, RawFd},
    ptr,
    sync::mpsc::{self, SyncSender},
    time::Duration,
};
use thiserror::Error;

pub(crate) const PROTOCOL_VERSION: u64 = 1;
pub(crate) const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const MAX_HELPER_FRAME_BYTES: usize = 8 * 1024 * 1024;
const XPC_CONNECTION_MACH_SERVICE_LISTENER: u64 = 1;

pub enum Event {
    Peer(Connection),
    Message(Message),
}

pub struct Connection(Object);
pub struct Request(Object);
pub struct Message(Object);
struct Object(*mut c_void);

/// Invalid native field in an authenticated macOS helper message.
#[derive(Debug, Error)]
pub enum FieldError {
    /// A required field was absent.
    #[error("helper message is missing field {key:?}")]
    Missing {
        /// Required protocol field.
        key: &'static CStr,
    },
    /// A field had a different native XPC type.
    #[error("helper message field {key:?} must be {expected:?}")]
    WrongType {
        /// Rejected protocol field.
        key: &'static CStr,
        /// Required native field type.
        expected: FieldKind,
    },
    /// A byte payload exceeded the checked IPC bound.
    #[error("helper message field {key:?} has {actual} bytes, exceeding {maximum}")]
    TooLarge {
        /// Rejected protocol field.
        key: &'static CStr,
        /// Received or attempted payload length.
        actual: usize,
        /// Maximum payload length.
        maximum: usize,
    },
    /// A nonempty native byte object lacked backing storage.
    #[error("helper message field {key:?} has a null data pointer for {length} bytes")]
    InvalidDataPointer {
        /// Rejected protocol field.
        key: &'static CStr,
        /// Reported native payload length.
        length: usize,
    },
}

/// Native XPC type required for a helper control field.
#[derive(Debug)]
pub enum FieldKind {
    /// An explicitly encoded unsigned 64-bit integer.
    UnsignedInteger,
    /// An immutable byte buffer.
    Data,
}

unsafe extern "C" {
    static _xpc_type_connection: u8;
    static _xpc_type_dictionary: u8;
    static _xpc_type_uint64: u8;
    static _xpc_type_data: u8;
    fn xpc_retain(object: *mut c_void) -> *mut c_void;
    fn xpc_release(object: *mut c_void);
    fn xpc_get_type(object: *mut c_void) -> *const c_void;
    fn xpc_connection_create_mach_service(
        name: *const libc::c_char,
        queue: *mut c_void,
        flags: u64,
    ) -> *mut c_void;
    fn xpc_connection_set_event_handler(
        connection: *mut c_void,
        block: &Block<dyn Fn(*mut c_void)>,
    );
    fn xpc_connection_resume(connection: *mut c_void);
    fn xpc_connection_cancel(connection: *mut c_void);
    fn xpc_connection_get_audit_token(connection: *mut c_void, token: *mut [u32; 8]);
    fn xpc_connection_send_message(connection: *mut c_void, message: *mut c_void);
    fn xpc_connection_send_message_with_reply(
        connection: *mut c_void,
        message: *mut c_void,
        queue: *mut c_void,
        block: &Block<dyn Fn(*mut c_void)>,
    );
    fn xpc_connection_send_barrier(connection: *mut c_void, block: &Block<dyn Fn()>);
    fn xpc_dictionary_create(
        keys: *const *const libc::c_char,
        values: *const *mut c_void,
        count: usize,
    ) -> *mut c_void;
    fn xpc_dictionary_set_uint64(message: *mut c_void, key: *const libc::c_char, value: u64);
    fn xpc_dictionary_get_uint64(message: *mut c_void, key: *const libc::c_char) -> u64;
    fn xpc_dictionary_get_value(message: *mut c_void, key: *const libc::c_char) -> *mut c_void;
    fn xpc_dictionary_set_data(
        message: *mut c_void,
        key: *const libc::c_char,
        bytes: *const c_void,
        length: usize,
    );
    fn xpc_data_get_length(data: *mut c_void) -> usize;
    fn xpc_data_get_bytes_ptr(data: *mut c_void) -> *const c_void;
    fn xpc_dictionary_set_fd(message: *mut c_void, key: *const libc::c_char, fd: RawFd);
    fn xpc_dictionary_dup_fd(message: *mut c_void, key: *const libc::c_char) -> RawFd;
    fn xpc_dictionary_get_audit_token(message: *mut c_void, token: *mut [u32; 8]);
    fn xpc_dictionary_create_reply(message: *mut c_void) -> *mut c_void;
    fn xpc_dictionary_get_remote_connection(message: *mut c_void) -> *mut c_void;
}

// Retained XPC references may move between threads. No Rust reference to
// mutable dictionary state is shared; incoming dictionaries are read-only.
unsafe impl Send for Object {}

impl Connection {
    pub fn client(name: &CStr) -> io::Result<Self> {
        let object =
            unsafe { xpc_connection_create_mach_service(name.as_ptr(), ptr::null_mut(), 0) };
        if object.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        let handler = RcBlock::new(|_event: *mut c_void| {});
        unsafe {
            xpc_connection_set_event_handler(object, &handler);
            xpc_connection_resume(object);
        }
        Ok(Self(Object(object)))
    }

    pub fn authenticated_listener(
        name: &CStr,
        sender: SyncSender<Event>,
        owner: (u32, u32),
    ) -> io::Result<Self> {
        Self::listen(name, sender, Some(owner))
    }

    fn listen(
        name: &CStr,
        sender: SyncSender<Event>,
        owner: Option<(u32, u32)>,
    ) -> io::Result<Self> {
        let object = unsafe {
            xpc_connection_create_mach_service(
                name.as_ptr(),
                ptr::null_mut(),
                XPC_CONNECTION_MACH_SERVICE_LISTENER,
            )
        };
        if object.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        let handler = RcBlock::new(move |peer: *mut c_void| unsafe {
            if xpc_get_type(peer) != (&raw const _xpc_type_connection).cast() {
                return;
            }
            if let Some(owner) = owner {
                let mut token = [0; 8];
                xpc_connection_get_audit_token(peer, &mut token);
                if (token[5], token[7]) != owner {
                    xpc_connection_cancel(peer);
                    return;
                }
            }
            let messages = sender.clone();
            let incoming = RcBlock::new(move |message: *mut c_void| {
                if xpc_get_type(message) == (&raw const _xpc_type_dictionary).cast() {
                    let event = Event::Message(Message(Object(xpc_retain(message))));
                    let _ = messages.try_send(event);
                }
            });
            let owned = Connection(Object(xpc_retain(peer)));
            xpc_connection_set_event_handler(peer, &incoming);
            // Queue ownership before enabling message delivery. A full
            // queue drops/cancels only this newly received connection.
            if sender.try_send(Event::Peer(owned)).is_ok() {
                xpc_connection_resume(peer);
            }
        });
        unsafe {
            xpc_connection_set_event_handler(object, &handler);
            xpc_connection_resume(object);
        }
        Ok(Self(Object(object)))
    }

    pub fn request(&self, request: Request) -> io::Result<Message> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let handler = RcBlock::new(move |reply: *mut c_void| unsafe {
            let result = if xpc_get_type(reply) == (&raw const _xpc_type_dictionary).cast() {
                Ok(Message(Object(xpc_retain(reply))))
            } else {
                Err(io::ErrorKind::ConnectionAborted.into())
            };
            let _ = sender.try_send(result);
        });
        unsafe {
            xpc_connection_send_message_with_reply(self.0.0, request.0.0, ptr::null_mut(), &handler)
        };
        receiver
            .recv_timeout(EXCHANGE_TIMEOUT)
            .map_err(receive_error)?
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe { xpc_connection_cancel(self.0.0) };
    }
}

impl Request {
    pub fn new() -> io::Result<Self> {
        let raw = unsafe { xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
        if raw.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        unsafe {
            xpc_dictionary_set_uint64(raw, c"version".as_ptr(), PROTOCOL_VERSION);
        }
        Ok(Self(Object(raw)))
    }

    pub fn set_number(&mut self, key: &CStr, value: u64) {
        unsafe { xpc_dictionary_set_uint64(self.0.0, key.as_ptr(), value) };
    }

    pub fn set_fd(&mut self, key: &CStr, fd: RawFd) {
        unsafe { xpc_dictionary_set_fd(self.0.0, key.as_ptr(), fd) };
    }

    pub fn set_data(&mut self, key: &'static CStr, bytes: &[u8]) -> Result<(), FieldError> {
        check_frame_length(key, bytes.len())?;
        // XPC copies the bytes before returning. The caller can release its
        // buffer without changing the queued command payload.
        unsafe {
            xpc_dictionary_set_data(self.0.0, key.as_ptr(), bytes.as_ptr().cast(), bytes.len());
        }
        Ok(())
    }
}

impl Message {
    pub fn number(&self, key: &'static CStr) -> Result<u64, FieldError> {
        self.field(key, FieldKind::UnsignedInteger)?;
        Ok(unsafe { xpc_dictionary_get_uint64(self.0.0, key.as_ptr()) })
    }

    pub fn data(&self, key: &'static CStr) -> Result<&[u8], FieldError> {
        let field = self.field(key, FieldKind::Data)?;
        let length = unsafe { xpc_data_get_length(field) };
        check_frame_length(key, length)?;
        if length == 0 {
            return Ok(&[]);
        }
        let pointer = unsafe { xpc_data_get_bytes_ptr(field) };
        if pointer.is_null() {
            return Err(FieldError::InvalidDataPointer { key, length });
        }
        // The immutable, retained dictionary owns this XPC data object. Its
        // borrowed bytes cannot outlive the message; no receiver allocation
        // occurs before checking the transport bound.
        Ok(unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) })
    }

    fn field(&self, key: &'static CStr, expected: FieldKind) -> Result<*mut c_void, FieldError> {
        let value = unsafe { xpc_dictionary_get_value(self.0.0, key.as_ptr()) };
        if value.is_null() {
            return Err(FieldError::Missing { key });
        }
        let expected_type = match expected {
            FieldKind::UnsignedInteger => (&raw const _xpc_type_uint64).cast(),
            FieldKind::Data => (&raw const _xpc_type_data).cast(),
        };
        if unsafe { xpc_get_type(value) } != expected_type {
            return Err(FieldError::WrongType { key, expected });
        }
        Ok(value)
    }

    pub fn sender_identity(&self) -> (u32, u32) {
        let mut audit = [0u32; 8];
        unsafe { xpc_dictionary_get_audit_token(self.0.0, &mut audit) };
        (audit[5], audit[7])
    }

    pub fn take_fd(&self, key: &CStr) -> io::Result<File> {
        let fd = unsafe { xpc_dictionary_dup_fd(self.0.0, key.as_ptr()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Adopt immediately so a failed flag operation still closes exactly
        // this duplicate. Received authority must not become ambient exec
        // inheritance before the helper assigns the explicit command streams.
        let file = unsafe { File::from_raw_fd(fd) };
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(file)
    }

    pub fn reply_data(&self, bytes: &[u8]) -> io::Result<()> {
        check_frame_length(c"payload", bytes.len()).map_err(io::Error::other)?;
        self.send_reply(0, Some(bytes))
    }

    fn send_reply(&self, status: u64, bytes: Option<&[u8]>) -> io::Result<()> {
        let raw = unsafe { xpc_dictionary_create_reply(self.0.0) };
        if raw.is_null() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let reply = Object(raw);
        let remote = unsafe { xpc_dictionary_get_remote_connection(self.0.0) };
        if remote.is_null() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let flushed = RcBlock::new(move || {
            let _ = sender.try_send(());
        });
        unsafe {
            xpc_dictionary_set_uint64(reply.0, c"version".as_ptr(), PROTOCOL_VERSION);
            xpc_dictionary_set_uint64(reply.0, c"result".as_ptr(), status);
            if let Some(bytes) = bytes {
                xpc_dictionary_set_data(
                    reply.0,
                    c"payload".as_ptr(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                );
            }
            xpc_connection_send_message(remote, reply.0);
            xpc_connection_send_barrier(remote, &flushed);
        }
        receiver
            .recv_timeout(EXCHANGE_TIMEOUT)
            .map_err(receive_error)
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        unsafe { xpc_release(self.0) };
    }
}

fn receive_error(error: mpsc::RecvTimeoutError) -> io::Error {
    match error {
        mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut.into(),
        mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe.into(),
    }
}

fn check_frame_length(key: &'static CStr, actual: usize) -> Result<(), FieldError> {
    if actual > MAX_HELPER_FRAME_BYTES {
        Err(FieldError::TooLarge {
            key,
            actual,
            maximum: MAX_HELPER_FRAME_BYTES,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FieldError, FieldKind, MAX_HELPER_FRAME_BYTES, Message, Request, io, mpsc, receive_error,
    };

    #[test]
    fn a_missing_or_wrong_type_result_is_not_a_successful_zero() {
        let mut request = Request::new().expect("request");
        request.set_number(c"zero", 0);
        request
            .set_data(c"wrong", &[0; 8])
            .expect("wrong type fixture");
        let message = Message(request.0);
        assert!(matches!(
            message.number(c"result"),
            Err(FieldError::Missing { .. })
        ));
        assert!(matches!(
            message.number(c"wrong"),
            Err(FieldError::WrongType {
                expected: FieldKind::UnsignedInteger,
                ..
            })
        ));
        assert_eq!(message.number(c"zero").expect("explicit native zero"), 0);
        assert!(matches!(
            message.data(c"zero"),
            Err(FieldError::WrongType {
                expected: FieldKind::Data,
                ..
            })
        ));
        assert!(matches!(
            message.data(c"absent"),
            Err(FieldError::Missing { .. })
        ));
    }

    #[test]
    fn command_bytes_are_owned_without_utf8_replacement() {
        let mut request = Request::new().expect("request");
        let mut payload = vec![b'/', 0xff, b'a', 0, b'b'];
        request
            .set_data(c"command", &payload)
            .expect("command bytes");
        request.set_data(c"empty", &[]).expect("empty native data");
        payload.fill(42);
        let message = Message(request.0);
        assert_eq!(
            message.data(c"command").expect("retained bytes"),
            &[b'/', 0xff, b'a', 0, b'b']
        );
        assert!(message.data(c"empty").expect("empty bytes").is_empty());
    }

    #[test]
    fn sender_and_receiver_check_the_frame_bound_independently() {
        let mut request = Request::new().expect("request");
        let mut payload = vec![0; MAX_HELPER_FRAME_BYTES];
        request
            .set_data(c"command", &payload)
            .expect("exact maximum");
        assert_eq!(
            Message(request.0)
                .data(c"command")
                .expect("maximum frame")
                .len(),
            payload.len()
        );
        payload.push(0);
        let mut request = Request::new().expect("request");
        assert!(matches!(
            request.set_data(c"command", &payload),
            Err(FieldError::TooLarge { .. })
        ));
        assert!(matches!(
            Message(request.0).data(c"command"),
            Err(FieldError::Missing { .. })
        ));

        // Construct a hostile native message without going through the checked
        // sender. The receiver must validate independently before copying.
        let request = Request::new().expect("hostile request");
        unsafe {
            super::xpc_dictionary_set_data(
                request.0.0,
                c"command".as_ptr(),
                payload.as_ptr().cast(),
                payload.len(),
            );
        }
        assert!(matches!(
            Message(request.0).data(c"command"),
            Err(FieldError::TooLarge { .. })
        ));
    }

    #[test]
    fn disconnected_response_channel_is_distinct_from_timeout() {
        assert_eq!(
            receive_error(mpsc::RecvTimeoutError::Disconnected).kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            receive_error(mpsc::RecvTimeoutError::Timeout).kind(),
            io::ErrorKind::TimedOut
        );
    }
}
