use super::*;
use serde_json::json;
use std::{
    io::Read,
    os::{
        fd::IntoRawFd,
        unix::net::{UnixDatagram, UnixListener, UnixStream},
    },
    time::Instant,
};

#[test]
fn control_file_and_socket_deliver_one_exact_frame_without_changing_shared_flags() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("control");
    let file = File::create(&path).unwrap();
    let fd = file.into_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let control = unsafe { ControlOutput::take(fd) }.unwrap();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    control
        .deliver(&json!({"marker":"control\nrecord"}))
        .unwrap();
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"{\"marker\":\"control\\nrecord\"}\n"
    );
    let (sender, mut receiver) = UnixStream::pair().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    unsafe { ControlOutput::take(sender.into_raw_fd()) }
        .unwrap()
        .deliver(&json!({"code":7}))
        .unwrap();
    let mut bytes = Vec::new();
    receiver.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"{\"code\":7}\n");
}

#[test]
fn invalid_control_descriptors_refuse_before_delivery() {
    for fd in [-1, 0, 1, 2, i32::MAX] {
        assert!(unsafe { ControlOutput::take(fd) }.is_err());
    }
    let file = File::open("Cargo.toml").unwrap();
    assert!(unsafe { ControlOutput::take(file.into_raw_fd()) }.is_err());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    assert!(unsafe { ControlOutput::take(file.into_raw_fd()) }.is_err());
    let datagram = UnixDatagram::unbound().unwrap();
    assert!(unsafe { ControlOutput::take(datagram.into_raw_fd()) }.is_err());
    let root = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(root.path().join("socket")).unwrap();
    assert!(unsafe { ControlOutput::take(listener.into_raw_fd()) }.is_err());
    let (sender, receiver) = UnixStream::pair().unwrap();
    drop(receiver);
    assert!(unsafe { ControlOutput::take(sender.into_raw_fd()) }.is_err());
}

#[test]
fn control_disconnect_after_validation_reports_failure_without_success_frame() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let control = unsafe { ControlOutput::take(sender.into_raw_fd()) }.unwrap();
    drop(receiver);
    assert!(control.deliver(&json!({"code":0})).is_err());
}

#[test]
fn stalled_control_delivery_has_a_deadline_and_bounded_frame_size() {
    let (sender, mut receiver) = UnixStream::pair().unwrap();
    let size: libc::c_int = 4096;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                sender.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        },
        0
    );
    let control = unsafe { ControlOutput::take(sender.into_raw_fd()) }.unwrap();
    let start = Instant::now();
    assert!(
        control
            .write(vec![b'x'; MAX_FRAME_BYTES], Duration::from_millis(20))
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    // Drain this unit test's worker before leaving; production exits the CLI.
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = Vec::new();
    receiver.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes.len(), MAX_FRAME_BYTES);
    let (sender, mut receiver) = UnixStream::pair().unwrap();
    let control = unsafe { ControlOutput::take(sender.into_raw_fd()) }.unwrap();
    assert!(control.deliver(&"x".repeat(MAX_FRAME_BYTES)).is_err());
    let mut bytes = Vec::new();
    receiver.read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty());
}

#[test]
fn nonblocking_control_backpressure_retries_without_changing_caller_flags() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    sender.set_nonblocking(true).unwrap();
    let mut filled = 0;
    loop {
        match sender.write(&[b'p'; 8192]) {
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            other => panic!("unexpected fill result {other:?}"),
        }
    }
    let raw = sender.into_raw_fd();
    let control = unsafe { ControlOutput::take(raw) }.unwrap();
    assert_ne!(
        unsafe { libc::fcntl(raw, libc::F_GETFL) } & libc::O_NONBLOCK,
        0
    );
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let reader = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(30));
        let mut bytes = Vec::new();
        receiver.read_to_end(&mut bytes).unwrap();
        bytes
    });
    control.deliver(&json!({"code":0})).unwrap();
    let bytes = reader.join().unwrap();
    assert!(bytes[..filled].iter().all(|b| *b == b'p'));
    assert_eq!(&bytes[filled..], b"{\"code\":0}\n");
}
