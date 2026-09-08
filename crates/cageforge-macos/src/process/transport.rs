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

pub(crate) const PROTOCOL_VERSION: u64 = 1;
pub(crate) const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const XPC_CONNECTION_MACH_SERVICE_LISTENER: u64 = 1;

pub enum Event {
    Peer(Connection),
    Message(Message),
}

pub struct Connection(Object);
pub struct Request(Object);
pub struct Message(Object);
struct Object(*mut c_void);

unsafe extern "C" {
    static _xpc_type_connection: u8;
    static _xpc_type_dictionary: u8;
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

    pub fn listener(name: &CStr, sender: SyncSender<Event>) -> io::Result<Self> {
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
}

impl Message {
    pub fn number(&self, key: &CStr) -> u64 {
        unsafe { xpc_dictionary_get_uint64(self.0.0, key.as_ptr()) }
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

    pub fn reply(&self, status: u64) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::{io, mpsc, receive_error};

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
