use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tokio::sync::mpsc;

const NETLINK_CONNECTOR: i32 = 11;
const CN_IDX_PROC: u32 = 1;
const CN_VAL_PROC: u32 = 1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_CN_MCAST_IGNORE: u32 = 2;
const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;
const NLMSG_DONE: u16 = 3;
const NLMSG_HEADER: usize = 16;
const CN_HEADER: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessEvent {
    Fork { parent: u32, child: u32 },
    Exec { pid: u32 },
    Exit { pid: u32 },
}

pub struct ProcessConnector {
    socket: Arc<OwnedFd>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ProcessConnector {
    pub fn spawn(
        sender: mpsc::Sender<ProcessEvent>,
        reconciliation_needed: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let socket = Arc::new(open_socket()?);
        subscribe(socket.as_raw_fd(), PROC_CN_MCAST_LISTEN)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_socket = Arc::clone(&socket);
        let worker_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("proton-split-proc".into())
            .spawn(move || {
                receive_loop(worker_socket, worker_stop, sender, reconciliation_needed)
            })?;
        Ok(Self {
            socket,
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for ProcessConnector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = subscribe(self.socket.as_raw_fd(), PROC_CN_MCAST_IGNORE);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn open_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket arguments are Linux UAPI constants and the returned fd is checked.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_CONNECTOR,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    address.nl_pid = std::process::id();
    address.nl_groups = CN_IDX_PROC;
    // SAFETY: address points to a fully initialized sockaddr_nl.
    let result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_nl).cast(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 250_000,
    };
    // SAFETY: timeout is a valid timeval for SO_RCVTIMEO.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn subscribe(socket: i32, operation: u32) -> io::Result<()> {
    let mut message = [0_u8; NLMSG_HEADER + CN_HEADER + 4];
    let message_len = message.len() as u32;
    put_u32(&mut message, 0, message_len);
    put_u16(&mut message, 4, NLMSG_DONE);
    put_u32(&mut message, 12, std::process::id());
    put_u32(&mut message, 16, CN_IDX_PROC);
    put_u32(&mut message, 20, CN_VAL_PROC);
    put_u16(&mut message, 32, 4);
    put_u32(&mut message, 36, operation);
    let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: the message and destination remain valid for the duration of sendto.
    let sent = unsafe {
        libc::sendto(
            socket,
            message.as_ptr().cast(),
            message.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn receive_loop(
    socket: Arc<OwnedFd>,
    stop: Arc<AtomicBool>,
    sender: mpsc::Sender<ProcessEvent>,
    reconciliation_needed: Arc<AtomicBool>,
) {
    let mut buffer = vec![0_u8; 16 * 1024];
    while !stop.load(Ordering::Acquire) {
        // SAFETY: buffer is valid and writable; recv only writes up to its length.
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                continue;
            }
            reconciliation_needed.store(true, Ordering::Release);
            eprintln!("proton-omarchy-splitd: process connector failed: {error}");
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        if received as usize == buffer.len() {
            // A full datagram may have been truncated. The periodic scan repairs
            // state without allowing an unbounded event backlog.
            reconciliation_needed.store(true, Ordering::Release);
        }
        for event in parse_messages(&buffer[..received as usize]) {
            match sender.try_send(event) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    reconciliation_needed.store(true, Ordering::Release);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            }
        }
    }
}

fn parse_messages(buffer: &[u8]) -> Vec<ProcessEvent> {
    let mut events = Vec::new();
    let mut offset = 0;
    while offset + NLMSG_HEADER + CN_HEADER <= buffer.len() {
        let length = get_u32(buffer, offset).unwrap_or(0) as usize;
        if length < NLMSG_HEADER + CN_HEADER || offset + length > buffer.len() {
            break;
        }
        let payload = offset + NLMSG_HEADER + CN_HEADER;
        let cn_length = get_u16(buffer, offset + NLMSG_HEADER + 16).unwrap_or(0) as usize;
        if cn_length >= 16 && payload + cn_length <= offset + length {
            let what = get_u32(buffer, payload).unwrap_or(0);
            let data = payload + 16;
            let event = match what {
                PROC_EVENT_FORK => Some(ProcessEvent::Fork {
                    parent: get_u32(buffer, data + 4).unwrap_or(0),
                    child: get_u32(buffer, data + 12).unwrap_or(0),
                }),
                PROC_EVENT_EXEC => Some(ProcessEvent::Exec {
                    pid: get_u32(buffer, data + 4).unwrap_or(0),
                }),
                PROC_EVENT_EXIT => Some(ProcessEvent::Exit {
                    pid: get_u32(buffer, data + 4).unwrap_or(0),
                }),
                _ => None,
            };
            if let Some(event) = event {
                events.push(event);
            }
        }
        offset += (length + 3) & !3;
    }
    events
}

fn put_u16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn get_u16(buffer: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        buffer.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn get_u32(buffer: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        buffer.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exec_tgid_from_connector_frame() {
        let mut frame = vec![0_u8; 60];
        let frame_len = frame.len() as u32;
        put_u32(&mut frame, 0, frame_len);
        put_u16(&mut frame, 32, 24);
        put_u32(&mut frame, 36, PROC_EVENT_EXEC);
        put_u32(&mut frame, 56, 4242);
        assert_eq!(
            parse_messages(&frame),
            vec![ProcessEvent::Exec { pid: 4242 }]
        );
    }
}
