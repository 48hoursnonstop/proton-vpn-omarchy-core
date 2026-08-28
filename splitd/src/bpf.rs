use crate::model::{parse_ip_range, ConfigMap, PolicyMap, SplitMode};
use ipnet::IpNet;
use std::{
    collections::HashMap,
    fs::File,
    io, mem,
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
const BPF_F_NO_PREALLOC: u32 = 1;
const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
const BPF_CGROUP_INET_SOCK_CREATE: u32 = 2;
const BPF_CGROUP_INET4_CONNECT: u32 = 10;
const BPF_CGROUP_INET6_CONNECT: u32 = 11;
const BPF_CGROUP_UDP4_SENDMSG: u32 = 14;
const BPF_CGROUP_UDP6_SENDMSG: u32 = 15;

const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_FUNC_GET_CURRENT_PID_TGID: i32 = 14;
const BPF_FUNC_GET_CURRENT_UID_GID: i32 = 15;
const BPF_FUNC_SETSOCKOPT: i32 = 49;
const BPF_FUNC_GETSOCKOPT: i32 = 57;
const BPF_PSEUDO_MAP_FD: u8 = 1;

const SOL_SOCKET: i32 = 1;
const SO_MARK: i32 = 36;

pub const FWMARK_VALUE: u32 = 245_447_468;
const MAX_TRACKED_PIDS: u32 = 65_536;
const MAX_USER_POLICIES: u32 = 64;
const MAX_DESTINATIONS: u32 = 64 * 256;
const CGROUP_PATH: &str = "/sys/fs/cgroup/user.slice";

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BpfInsn {
    code: u8,
    registers: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            registers: (dst & 0x0f) | ((src & 0x0f) << 4),
            off,
            imm,
        }
    }
}

// Command-specific prefixes of Linux's union bpf_attr. Typed layouts make an
// incorrect UAPI offset fail in tests instead of only at verifier time.
#[repr(C)]
#[derive(Default)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
}

#[repr(C)]
#[derive(Default)]
struct MapElementAttr {
    map_fd: u32,
    padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct ProgramLoadAttr {
    program_type: u32,
    instruction_count: u32,
    instructions: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buffer: u64,
    kernel_version: u32,
    program_flags: u32,
    program_name: [u8; 16],
    program_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
#[derive(Default)]
struct ProgramAttachAttr {
    target_fd: u32,
    program_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_program_fd: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ipv4LpmKey {
    prefix_len: u32,
    uid: u32,
    address: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ipv6LpmKey {
    prefix_len: u32,
    uid: u32,
    address: [u8; 16],
}

struct AttachedProgram {
    fd: OwnedFd,
    attach_type: u32,
}

pub struct SocketMarker {
    cgroup: File,
    pid_map: OwnedFd,
    mode_map: OwnedFd,
    ipv4_map: OwnedFd,
    ipv6_map: OwnedFd,
    bypass_ipv4_map: OwnedFd,
    bypass_ipv6_map: OwnedFd,
    programs: Vec<AttachedProgram>,
    configs: ConfigMap,
    destination_policies: PolicyMap,
}

impl SocketMarker {
    pub fn attach() -> io::Result<Self> {
        let pid_map =
            create_map::<u32, u32>("proton_pid_map", BPF_MAP_TYPE_HASH, MAX_TRACKED_PIDS, 0)?;
        let mode_map =
            create_map::<u32, u32>("proton_uid_map", BPF_MAP_TYPE_HASH, MAX_USER_POLICIES, 0)?;
        let ipv4_map = create_map::<Ipv4LpmKey, u32>(
            "proton_ip4_map",
            BPF_MAP_TYPE_LPM_TRIE,
            MAX_DESTINATIONS,
            BPF_F_NO_PREALLOC,
        )?;
        let ipv6_map = create_map::<Ipv6LpmKey, u32>(
            "proton_ip6_map",
            BPF_MAP_TYPE_LPM_TRIE,
            MAX_DESTINATIONS,
            BPF_F_NO_PREALLOC,
        )?;
        let bypass_ipv4_map = create_map::<Ipv4LpmKey, u32>(
            "proton_bp4_map",
            BPF_MAP_TYPE_LPM_TRIE,
            MAX_DESTINATIONS,
            BPF_F_NO_PREALLOC,
        )?;
        let bypass_ipv6_map = create_map::<Ipv6LpmKey, u32>(
            "proton_bp6_map",
            BPF_MAP_TYPE_LPM_TRIE,
            MAX_DESTINATIONS,
            BPF_F_NO_PREALLOC,
        )?;
        let cgroup = File::open(CGROUP_PATH)?;
        let mut marker = Self {
            cgroup,
            pid_map,
            mode_map,
            ipv4_map,
            ipv6_map,
            bypass_ipv4_map,
            bypass_ipv6_map,
            programs: Vec::with_capacity(5),
            configs: ConfigMap::new(),
            destination_policies: PolicyMap::new(),
        };

        marker.load_and_attach(
            BPF_PROG_TYPE_CGROUP_SOCK,
            BPF_CGROUP_INET_SOCK_CREATE,
            "proton_split",
            socket_mark_program(marker.pid_map.as_raw_fd()),
        )?;
        for (attach_type, ipv6, name) in [
            (BPF_CGROUP_INET4_CONNECT, false, "proton_dst4"),
            (BPF_CGROUP_INET6_CONNECT, true, "proton_dst6"),
            (BPF_CGROUP_UDP4_SENDMSG, false, "proton_udp4"),
            (BPF_CGROUP_UDP6_SENDMSG, true, "proton_udp6"),
        ] {
            marker.load_and_attach(
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                attach_type,
                name,
                destination_mark_program(
                    marker.mode_map.as_raw_fd(),
                    if ipv6 {
                        marker.ipv6_map.as_raw_fd()
                    } else {
                        marker.ipv4_map.as_raw_fd()
                    },
                    if ipv6 {
                        marker.bypass_ipv6_map.as_raw_fd()
                    } else {
                        marker.bypass_ipv4_map.as_raw_fd()
                    },
                    ipv6,
                ),
            )?;
        }
        Ok(marker)
    }

    fn load_and_attach(
        &mut self,
        program_type: u32,
        attach_type: u32,
        name: &str,
        instructions: Vec<BpfInsn>,
    ) -> io::Result<()> {
        let program = load_program(program_type, attach_type, name, &instructions)?;
        attach_program(self.cgroup.as_raw_fd(), program.as_raw_fd(), attach_type)?;
        self.programs.push(AttachedProgram {
            fd: program,
            attach_type,
        });
        Ok(())
    }

    pub fn set_excluded(&self, pid: u32, excluded: bool) -> io::Result<()> {
        if excluded {
            map_update(self.pid_map.as_raw_fd(), &pid, &1_u32)
        } else {
            map_delete(self.pid_map.as_raw_fd(), &pid)
        }
    }

    pub fn sync_configs(
        &mut self,
        configs: &ConfigMap,
        destination_policies: &PolicyMap,
    ) -> io::Result<()> {
        if configs == &self.configs && destination_policies == &self.destination_policies {
            return Ok(());
        }
        let previous_configs = self.configs.clone();
        let previous_policies = self.destination_policies.clone();
        if let Err(error) = self.replace_maps(
            &previous_configs,
            &previous_policies,
            configs,
            destination_policies,
        ) {
            let rollback = self.replace_maps(
                configs,
                destination_policies,
                &previous_configs,
                &previous_policies,
            );
            return Err(match rollback {
                Ok(()) => error,
                Err(rollback) => io::Error::new(
                    error.kind(),
                    format!("{error}; kernel policy rollback also failed: {rollback}"),
                ),
            });
        }
        self.configs = configs.clone();
        self.destination_policies = destination_policies.clone();
        Ok(())
    }

    fn replace_maps(
        &self,
        old_configs: &ConfigMap,
        old_policies: &PolicyMap,
        new_configs: &ConfigMap,
        new_policies: &PolicyMap,
    ) -> io::Result<()> {
        for (uid, config) in old_configs {
            let uid = u32::from(*uid);
            let _ = map_delete(self.mode_map.as_raw_fd(), &uid);
            for range in &config.ip_ranges {
                self.delete_range(uid, range)?;
            }
        }
        for (uid, ranges) in old_policies {
            for range in ranges {
                self.delete_bypass_range(u32::from(*uid), range)?;
            }
        }
        for (uid, config) in new_configs.iter().filter(|(_, config)| config.has_rules()) {
            let uid = u32::from(*uid);
            let mode = u32::from(config.mode == SplitMode::Include);
            map_update(self.mode_map.as_raw_fd(), &uid, &mode)?;
            for range in &config.ip_ranges {
                self.update_range(uid, range)?;
            }
        }
        for (uid, ranges) in new_policies {
            for range in ranges {
                self.update_bypass_range(u32::from(*uid), range)?;
            }
        }
        Ok(())
    }

    fn update_range(&self, uid: u32, value: &str) -> io::Result<()> {
        match parsed_range(value)? {
            IpNet::V4(network) => map_update(
                self.ipv4_map.as_raw_fd(),
                &ipv4_key(uid, network.network(), network.prefix_len()),
                &1_u32,
            ),
            IpNet::V6(network) => map_update(
                self.ipv6_map.as_raw_fd(),
                &ipv6_key(uid, network.network(), network.prefix_len()),
                &1_u32,
            ),
        }
    }

    fn delete_range(&self, uid: u32, value: &str) -> io::Result<()> {
        match parsed_range(value)? {
            IpNet::V4(network) => map_delete(
                self.ipv4_map.as_raw_fd(),
                &ipv4_key(uid, network.network(), network.prefix_len()),
            ),
            IpNet::V6(network) => map_delete(
                self.ipv6_map.as_raw_fd(),
                &ipv6_key(uid, network.network(), network.prefix_len()),
            ),
        }
    }

    fn update_bypass_range(&self, uid: u32, value: &str) -> io::Result<()> {
        match parsed_range(value)? {
            IpNet::V4(network) => map_update(
                self.bypass_ipv4_map.as_raw_fd(),
                &ipv4_key(uid, network.network(), network.prefix_len()),
                &1_u32,
            ),
            IpNet::V6(network) => map_update(
                self.bypass_ipv6_map.as_raw_fd(),
                &ipv6_key(uid, network.network(), network.prefix_len()),
                &1_u32,
            ),
        }
    }

    fn delete_bypass_range(&self, uid: u32, value: &str) -> io::Result<()> {
        match parsed_range(value)? {
            IpNet::V4(network) => map_delete(
                self.bypass_ipv4_map.as_raw_fd(),
                &ipv4_key(uid, network.network(), network.prefix_len()),
            ),
            IpNet::V6(network) => map_delete(
                self.bypass_ipv6_map.as_raw_fd(),
                &ipv6_key(uid, network.network(), network.prefix_len()),
            ),
        }
    }
}

impl Drop for SocketMarker {
    fn drop(&mut self) {
        for program in self.programs.iter().rev() {
            let _ = detach_program(
                self.cgroup.as_raw_fd(),
                program.fd.as_raw_fd(),
                program.attach_type,
            );
        }
    }
}

fn parsed_range(value: &str) -> io::Result<IpNet> {
    parse_ip_range(value).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn ipv4_key(uid: u32, address: Ipv4Addr, prefix: u8) -> Ipv4LpmKey {
    Ipv4LpmKey {
        prefix_len: 32 + u32::from(prefix),
        uid,
        address: address.octets(),
    }
}

fn ipv6_key(uid: u32, address: Ipv6Addr, prefix: u8) -> Ipv6LpmKey {
    Ipv6LpmKey {
        prefix_len: 32 + u32::from(prefix),
        uid,
        address: address.octets(),
    }
}

fn create_map<K, V>(
    name: &str,
    map_type: u32,
    max_entries: u32,
    flags: u32,
) -> io::Result<OwnedFd> {
    let mut attr = MapCreateAttr {
        map_type,
        key_size: mem::size_of::<K>() as u32,
        value_size: mem::size_of::<V>() as u32,
        max_entries,
        map_flags: flags,
        map_name: kernel_name(name)?,
        ..MapCreateAttr::default()
    };
    let fd = bpf(BPF_MAP_CREATE, &mut attr)?;
    // SAFETY: bpf returned a new owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn map_update<K, V>(map_fd: i32, key: &K, value: &V) -> io::Result<()> {
    let mut attr = MapElementAttr {
        map_fd: map_fd as u32,
        key: (key as *const K) as u64,
        value: (value as *const V) as u64,
        ..MapElementAttr::default()
    };
    bpf(BPF_MAP_UPDATE_ELEM, &mut attr).map(|_| ())
}

fn map_delete<K>(map_fd: i32, key: &K) -> io::Result<()> {
    let mut attr = MapElementAttr {
        map_fd: map_fd as u32,
        key: (key as *const K) as u64,
        ..MapElementAttr::default()
    };
    match bpf(BPF_MAP_DELETE_ELEM, &mut attr) {
        Ok(_) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(error) => Err(error),
    }
}

fn load_program(
    program_type: u32,
    attach_type: u32,
    name: &str,
    instructions: &[BpfInsn],
) -> io::Result<OwnedFd> {
    let license = b"GPL\0";
    let mut log = vec![0_u8; 64 * 1024];
    let mut attr = ProgramLoadAttr {
        program_type,
        instruction_count: instructions.len() as u32,
        instructions: instructions.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log_buffer: log.as_mut_ptr() as u64,
        program_name: kernel_name(name)?,
        expected_attach_type: attach_type,
        ..ProgramLoadAttr::default()
    };
    match bpf(BPF_PROG_LOAD, &mut attr) {
        Ok(fd) => {
            // SAFETY: bpf returned a new owned file descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
        Err(error) => {
            let end = log.iter().position(|byte| *byte == 0).unwrap_or(log.len());
            let verifier = String::from_utf8_lossy(&log[..end]).trim().to_owned();
            Err(io::Error::new(
                error.kind(),
                if verifier.is_empty() {
                    format!("unable to load split-tunneling eBPF program {name}: {error}")
                } else {
                    format!(
                        "unable to load split-tunneling eBPF program {name}: {error}: {verifier}"
                    )
                },
            ))
        }
    }
}

fn attach_program(cgroup_fd: i32, program_fd: i32, attach_type: u32) -> io::Result<()> {
    let mut attr = ProgramAttachAttr {
        target_fd: cgroup_fd as u32,
        program_fd: program_fd as u32,
        attach_type,
        ..ProgramAttachAttr::default()
    };
    bpf(BPF_PROG_ATTACH, &mut attr).map(|_| ())
}

fn detach_program(cgroup_fd: i32, program_fd: i32, attach_type: u32) -> io::Result<()> {
    let mut attr = ProgramAttachAttr {
        target_fd: cgroup_fd as u32,
        program_fd: program_fd as u32,
        attach_type,
        ..ProgramAttachAttr::default()
    };
    bpf(BPF_PROG_DETACH, &mut attr).map(|_| ())
}

fn kernel_name(value: &str) -> io::Result<[u8; 16]> {
    if value.is_empty() || value.len() >= 16 || value.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "eBPF object names must contain 1 to 15 non-NUL bytes",
        ));
    }
    let mut name = [0_u8; 16];
    name[..value.len()].copy_from_slice(value.as_bytes());
    Ok(name)
}

fn socket_mark_program(pid_map_fd: i32) -> Vec<BpfInsn> {
    let mut program = ProgramBuilder::default();
    program.mov_reg(6, 1);
    program.call(BPF_FUNC_GET_CURRENT_PID_TGID);
    program.rsh_imm(0, 32);
    program.store_reg32(10, -4, 0);
    program.load_map(1, pid_map_fd);
    program.stack_pointer(2, -4);
    program.call(BPF_FUNC_MAP_LOOKUP_ELEM);
    program.jump_eq_imm(0, 0, "allow");
    program.store_imm32(6, 16, FWMARK_VALUE as i32);
    program.label("allow");
    program.mov_imm(0, 1);
    program.exit();
    program.finish()
}

fn destination_mark_program(
    mode_map_fd: i32,
    range_map_fd: i32,
    bypass_map_fd: i32,
    ipv6: bool,
) -> Vec<BpfInsn> {
    let mut program = ProgramBuilder::default();
    program.mov_reg(6, 1);
    program.call(BPF_FUNC_GET_CURRENT_UID_GID);
    program.store_reg32(10, -4, 0);

    if ipv6 {
        program.store_imm32(10, -24, 160);
        program.load32(0, 10, -4);
        program.store_reg32(10, -20, 0);
        program.load64(0, 6, 8);
        program.store_reg64(10, -16, 0);
        program.load64(0, 6, 16);
        program.store_reg64(10, -8, 0);
    } else {
        program.store_imm32(10, -16, 64);
        program.load32(0, 10, -4);
        program.store_reg32(10, -12, 0);
        program.load32(0, 6, 4);
        program.store_reg32(10, -8, 0);
    }
    program.load_map(1, bypass_map_fd);
    program.stack_pointer(2, if ipv6 { -24 } else { -16 });
    program.call(BPF_FUNC_MAP_LOOKUP_ELEM);
    program.jump_eq_imm(0, 0, "split_policy");
    program.mov_imm(7, 0);
    program.jump("mark_socket");

    program.label("split_policy");
    program.load_map(1, mode_map_fd);
    program.stack_pointer(2, -4);
    program.call(BPF_FUNC_MAP_LOOKUP_ELEM);
    program.jump_eq_imm(0, 0, "allow");
    program.load32(7, 0, 0);
    program.load_map(1, range_map_fd);
    program.stack_pointer(2, if ipv6 { -24 } else { -16 });
    program.call(BPF_FUNC_MAP_LOOKUP_ELEM);
    program.jump_eq_imm(0, 0, "allow");
    program.label("mark_socket");
    program.jump_eq_imm(7, 0, "set_mark");
    program.get_socket_mark(6, -28);
    program.load32(0, 10, -28);
    program.jump_ne_imm(0, FWMARK_VALUE as i32, "allow");
    program.set_socket_mark(6, -28, 0);
    program.jump("allow");
    program.label("set_mark");
    program.set_socket_mark(6, -28, FWMARK_VALUE as i32);
    program.label("allow");
    program.mov_imm(0, 1);
    program.exit();
    program.finish()
}

#[derive(Default)]
struct ProgramBuilder {
    instructions: Vec<BpfInsn>,
    labels: HashMap<&'static str, usize>,
    fixups: Vec<(usize, &'static str)>,
}

impl ProgramBuilder {
    fn emit(&mut self, instruction: BpfInsn) {
        self.instructions.push(instruction);
    }

    fn mov_reg(&mut self, dst: u8, src: u8) {
        self.emit(BpfInsn::new(0xbf, dst, src, 0, 0));
    }

    fn mov_imm(&mut self, dst: u8, value: i32) {
        self.emit(BpfInsn::new(0xb7, dst, 0, 0, value));
    }

    fn rsh_imm(&mut self, dst: u8, bits: i32) {
        self.emit(BpfInsn::new(0x77, dst, 0, 0, bits));
    }

    fn load32(&mut self, dst: u8, src: u8, offset: i16) {
        self.emit(BpfInsn::new(0x61, dst, src, offset, 0));
    }

    fn load64(&mut self, dst: u8, src: u8, offset: i16) {
        self.emit(BpfInsn::new(0x79, dst, src, offset, 0));
    }

    fn store_imm32(&mut self, dst: u8, offset: i16, value: i32) {
        self.emit(BpfInsn::new(0x62, dst, 0, offset, value));
    }

    fn store_reg32(&mut self, dst: u8, offset: i16, src: u8) {
        self.emit(BpfInsn::new(0x63, dst, src, offset, 0));
    }

    fn store_reg64(&mut self, dst: u8, offset: i16, src: u8) {
        self.emit(BpfInsn::new(0x7b, dst, src, offset, 0));
    }

    fn stack_pointer(&mut self, dst: u8, offset: i32) {
        self.mov_reg(dst, 10);
        self.emit(BpfInsn::new(0x07, dst, 0, 0, offset));
    }

    fn load_map(&mut self, dst: u8, map_fd: i32) {
        self.emit(BpfInsn::new(0x18, dst, BPF_PSEUDO_MAP_FD, 0, map_fd));
        self.emit(BpfInsn::new(0x00, 0, 0, 0, 0));
    }

    fn call(&mut self, helper: i32) {
        self.emit(BpfInsn::new(0x85, 0, 0, 0, helper));
    }

    fn socket_option_args(&mut self, context: u8, stack_offset: i32) {
        self.mov_reg(1, context);
        self.mov_imm(2, SOL_SOCKET);
        self.mov_imm(3, SO_MARK);
        self.stack_pointer(4, stack_offset);
        self.mov_imm(5, mem::size_of::<u32>() as i32);
    }

    fn get_socket_mark(&mut self, context: u8, stack_offset: i32) {
        self.socket_option_args(context, stack_offset);
        self.call(BPF_FUNC_GETSOCKOPT);
    }

    fn set_socket_mark(&mut self, context: u8, stack_offset: i32, mark: i32) {
        self.store_imm32(10, stack_offset as i16, mark);
        self.socket_option_args(context, stack_offset);
        self.call(BPF_FUNC_SETSOCKOPT);
    }

    fn jump_eq_imm(&mut self, register: u8, value: i32, label: &'static str) {
        self.fixups.push((self.instructions.len(), label));
        self.emit(BpfInsn::new(0x15, register, 0, 0, value));
    }

    fn jump_ne_imm(&mut self, register: u8, value: i32, label: &'static str) {
        self.fixups.push((self.instructions.len(), label));
        self.emit(BpfInsn::new(0x55, register, 0, 0, value));
    }

    fn jump(&mut self, label: &'static str) {
        self.fixups.push((self.instructions.len(), label));
        self.emit(BpfInsn::new(0x05, 0, 0, 0, 0));
    }

    fn label(&mut self, label: &'static str) {
        assert!(self.labels.insert(label, self.instructions.len()).is_none());
    }

    fn exit(&mut self) {
        self.emit(BpfInsn::new(0x95, 0, 0, 0, 0));
    }

    fn finish(mut self) -> Vec<BpfInsn> {
        for (instruction, label) in self.fixups {
            let destination = *self.labels.get(label).expect("missing eBPF label");
            self.instructions[instruction].off =
                i16::try_from(destination as isize - instruction as isize - 1)
                    .expect("eBPF jump exceeds i16 range");
        }
        self.instructions
    }
}

fn bpf<T>(command: u32, attr: &mut T) -> io::Result<i32> {
    // SAFETY: each call passes a repr(C), zero-initialized command-specific
    // prefix of union bpf_attr and the exact initialized structure size.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command,
            (attr as *mut T).cast::<libc::c_void>(),
            mem::size_of::<T>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_specific_uapi_layouts_match_linux() {
        assert_eq!(mem::size_of::<MapCreateAttr>(), 44);
        assert_eq!(mem::size_of::<MapElementAttr>(), 32);
        assert_eq!(mem::size_of::<ProgramLoadAttr>(), 72);
        assert_eq!(mem::size_of::<ProgramAttachAttr>(), 20);
        assert_eq!(mem::size_of::<Ipv4LpmKey>(), 12);
        assert_eq!(mem::size_of::<Ipv6LpmKey>(), 24);
    }

    #[test]
    fn socket_program_uses_tgid_and_writes_the_proton_fwmark() {
        let program = socket_mark_program(19);
        assert!(program
            .iter()
            .any(|instruction| *instruction == BpfInsn::new(0x77, 0, 0, 0, 32)));
        assert!(program.iter().any(|instruction| {
            *instruction == BpfInsn::new(0x62, 6, 0, 16, FWMARK_VALUE as i32)
        }));
        assert_eq!(program.last().unwrap().code, 0x95);
    }

    #[test]
    fn destination_programs_have_resolved_forward_jumps() {
        for program in [
            destination_mark_program(17, 18, 20, false),
            destination_mark_program(17, 19, 21, true),
        ] {
            assert!(program
                .iter()
                .filter(|instruction| matches!(instruction.code, 0x05 | 0x15 | 0x55))
                .all(|instruction| instruction.off > 0));
            assert_eq!(program.last().unwrap().code, 0x95);
            assert!(program.iter().any(|instruction| {
                *instruction == BpfInsn::new(0x85, 0, 0, 0, BPF_FUNC_SETSOCKOPT)
            }));
            assert!(program.iter().any(|instruction| {
                *instruction == BpfInsn::new(0x85, 0, 0, 0, BPF_FUNC_GETSOCKOPT)
            }));
        }
    }

    #[test]
    fn lpm_keys_scope_prefixes_by_uid() {
        let ipv4 = ipv4_key(1000, "192.0.2.0".parse().unwrap(), 24);
        assert_eq!(ipv4.prefix_len, 56);
        assert_eq!(ipv4.address, [192, 0, 2, 0]);
        let ipv6 = ipv6_key(1000, "2001:db8::".parse().unwrap(), 32);
        assert_eq!(ipv6.prefix_len, 64);
        assert_eq!(&ipv6.address[..4], &[0x20, 0x01, 0x0d, 0xb8]);
    }
}
