use super::*;

fn execute_destination(
    initial_mark: u32,
    mode: Option<u32>,
    range: bool,
    bypass: bool,
    ipv6: bool,
    excluded_app: bool,
) -> u32 {
    let program = destination_mark_program(10, 11, 12, 13, ipv6);
    let mut registers = [0_u64; 11];
    let mut memory = vec![0_u8; 4096];
    registers[1] = 1024;
    registers[10] = 512;
    if ipv6 {
        memory[1032..1048].copy_from_slice(&"2001:db8::1234".parse::<Ipv6Addr>().unwrap().octets());
    } else {
        memory[1028..1032].copy_from_slice(&[198, 51, 100, 7]);
    }
    memory[2048..2052].copy_from_slice(&mode.unwrap_or_default().to_ne_bytes());
    let mut mark = initial_mark;
    let mut pc = 0;
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 200, "instruction budget exceeded");
        let instruction = program[pc];
        let dst = (instruction.registers & 15) as usize;
        let src = (instruction.registers >> 4) as usize;
        let address = registers[dst].wrapping_add(instruction.off as i64 as u64) as usize;
        let source_address = registers[src].wrapping_add(instruction.off as i64 as u64) as usize;
        match instruction.code {
            0xbf => registers[dst] = registers[src],
            0xb7 => registers[dst] = instruction.imm as i64 as u64,
            0x77 => registers[dst] >>= instruction.imm,
            0x07 => registers[dst] = registers[dst].wrapping_add(instruction.imm as i64 as u64),
            0x61 => {
                registers[dst] = u32::from_ne_bytes(
                    memory[source_address..source_address + 4]
                        .try_into()
                        .unwrap(),
                ) as u64
            }
            0x79 => {
                registers[dst] = u64::from_ne_bytes(
                    memory[source_address..source_address + 8]
                        .try_into()
                        .unwrap(),
                )
            }
            0x62 => memory[address..address + 4].copy_from_slice(&instruction.imm.to_ne_bytes()),
            0x63 => {
                memory[address..address + 4].copy_from_slice(&(registers[src] as u32).to_ne_bytes())
            }
            0x7b => memory[address..address + 8].copy_from_slice(&registers[src].to_ne_bytes()),
            0x18 => {
                registers[dst] = instruction.imm as u64;
                pc += 1;
            }
            0x15 if registers[dst] == instruction.imm as i64 as u64 => {
                pc = (pc as isize + instruction.off as isize) as usize
            }
            0x55 if registers[dst] != instruction.imm as i64 as u64 => {
                pc = (pc as isize + instruction.off as isize) as usize
            }
            0x15 | 0x55 => {}
            0x05 => pc = (pc as isize + instruction.off as isize) as usize,
            0x85 => match instruction.imm {
                BPF_FUNC_GET_CURRENT_PID_TGID => registers[0] = 42_u64 << 32,
                BPF_FUNC_GET_CURRENT_UID_GID => registers[0] = 1000,
                BPF_FUNC_MAP_LOOKUP_ELEM => {
                    let p = registers[2] as usize;
                    let key_uid = u32::from_ne_bytes(memory[p..p + 4].try_into().unwrap());
                    let range_uid = u32::from_ne_bytes(memory[p + 4..p + 8].try_into().unwrap());
                    let found = match registers[1] {
                        10 => excluded_app && key_uid == 42,
                        11 => mode.is_some() && key_uid == 1000,
                        12 => range && range_uid == 1000,
                        13 => bypass && range_uid == 1000,
                        other => panic!("unknown map {other}"),
                    };
                    registers[0] = if found { 2048 } else { 0 };
                }
                BPF_FUNC_GETSOCKOPT => {
                    let p = registers[4] as usize;
                    memory[p..p + 4].copy_from_slice(&mark.to_ne_bytes());
                    registers[0] = 0;
                }
                BPF_FUNC_SETSOCKOPT => {
                    let p = registers[4] as usize;
                    mark = u32::from_ne_bytes(memory[p..p + 4].try_into().unwrap());
                    registers[0] = 0;
                }
                other => panic!("unknown helper {other}"),
            },
            0x95 => return mark,
            other => panic!("unknown opcode {other:x}"),
        }
        pc += 1;
    }
}

#[test]
fn ipv6_ip_rules_apply_to_the_configured_user() {
    assert_eq!(
        execute_destination(0, Some(0), true, false, true, false),
        FWMARK_VALUE
    );
    assert_eq!(
        execute_destination(FWMARK_VALUE, Some(1), true, false, true, true),
        0
    );
}

#[test]
fn reused_udp_socket_recomputes_policy_for_each_destination() {
    for ipv6 in [false, true] {
        for app in [false, true] {
            let baseline = if app { FWMARK_VALUE } else { 0 };
            for mode in [Some(0), Some(1)] {
                let first = execute_destination(baseline, mode, true, false, ipv6, app);
                assert_eq!(first, if mode == Some(0) { FWMARK_VALUE } else { 0 });
                let second = execute_destination(first, mode, false, false, ipv6, app);
                assert_eq!(
                    second, baseline,
                    "destination decision must not replace the app baseline"
                );
                let third = execute_destination(second, mode, true, false, ipv6, app);
                assert_eq!(third, first);
            }
        }
    }
}

#[test]
fn lan_exception_does_not_exclude_later_public_udp_traffic() {
    for ipv6 in [false, true] {
        let local = execute_destination(0, None, false, true, ipv6, false);
        assert_eq!(local, FWMARK_VALUE);
        assert_eq!(
            execute_destination(local, None, false, false, ipv6, false),
            0
        );
    }
}

#[test]
fn app_policy_changes_replace_old_marks_without_erasing_foreign_marks() {
    for ipv6 in [false, true] {
        assert_eq!(
            execute_destination(FWMARK_VALUE, Some(0), false, false, ipv6, false),
            0
        );
        assert_eq!(
            execute_destination(0, Some(0), false, false, ipv6, true),
            FWMARK_VALUE
        );
        assert_eq!(
            execute_destination(73, Some(0), false, false, ipv6, false),
            73
        );
    }
}
