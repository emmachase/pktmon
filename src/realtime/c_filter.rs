use std::{ffi::OsStr, fmt::Debug, os::windows::ffi::OsStrExt};

use cidr::AnyIpCidr;

use crate::{
    ctypes::{CIPAddr, CIPv6Addr, CMacAddr},
    filter::{Encapsulation, OptionPair, PktMonFilter, TransportProtocol},
};

const PACKETMONITOR_MAX_NAME_LENGTH: usize = 64;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMonitorProtocolConstraint {
    name: [u16; PACKETMONITOR_MAX_NAME_LENGTH],

    flags: Flags,

    // Ethernet frame
    mac_1: CMacAddr,
    mac_2: CMacAddr,

    vlan_id: u16,

    ether_type: u16,

    // IP header
    dscp: u16,
    transport_protocol: u8,

    ip_1: CIPAddr,
    ip_2: CIPAddr,

    ip_1_prefix: u8,
    ip_2_prefix: u8,

    // TCP or UDP header
    port_1: u16,
    port_2: u16,

    tcp_flags: u8,

    // Encapsulation
    encap_type: u32,
    vxlan_port: u16,

    // Counters
    packets: u64,
    bytes: u64,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
struct Flags {
    pub raw: u32,
}

impl Debug for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Flags {{ mac_1: {}, mac_2: {}, vlan_id: {}, data_link_protocol: {}, dscp: {}, transport_protocol: {}, ip_src: {}, ip_dst: {}, ip_v6: {}, ip_src_prefix: {}, ip_dst_prefix: {}, port_src: {}, port_dst: {}, tcp_flags: {}, encapsulation: {}, vxlan_port: {}, heartbeat: {} }}",
            self.mac_1(),
            self.mac_2(),
            self.vlan_id(),
            self.ether_type(),
            self.dscp(),
            self.transport_protocol(),
            self.ip_1(),
            self.ip_2(),
            self.ip_v6(),
            self.ip_1_prefix(),
            self.ip_2_prefix(),
            self.port_1(),
            self.port_2(),
            self.tcp_flags(),
            self.encap_type(),
            self.vxlan_port(),
            self.cluster_heartbeat()
        )
    }
}

fn test_bit(value: u32, bit: u32) -> bool {
    (value & (1 << bit)) != 0
}

fn set_bit(value: u32, bit: u32, set: bool) -> u32 {
    if set {
        value | (1 << bit)
    } else {
        value & !(1 << bit)
    }
}

impl Flags {
    pub fn mac_1(&self) -> bool {
        test_bit(self.raw, 0)
    }
    pub fn mac_2(&self) -> bool {
        test_bit(self.raw, 1)
    }
    pub fn vlan_id(&self) -> bool {
        test_bit(self.raw, 2)
    }
    pub fn ether_type(&self) -> bool {
        test_bit(self.raw, 3)
    }
    pub fn dscp(&self) -> bool {
        test_bit(self.raw, 4)
    }
    pub fn transport_protocol(&self) -> bool {
        test_bit(self.raw, 5)
    }
    pub fn ip_1(&self) -> bool {
        test_bit(self.raw, 6)
    }
    pub fn ip_2(&self) -> bool {
        test_bit(self.raw, 7)
    }
    pub fn ip_v6(&self) -> bool {
        test_bit(self.raw, 8)
    }
    pub fn ip_1_prefix(&self) -> bool {
        test_bit(self.raw, 9)
    }
    pub fn ip_2_prefix(&self) -> bool {
        test_bit(self.raw, 10)
    }
    pub fn port_1(&self) -> bool {
        test_bit(self.raw, 11)
    }
    pub fn port_2(&self) -> bool {
        test_bit(self.raw, 12)
    }
    pub fn tcp_flags(&self) -> bool {
        test_bit(self.raw, 13)
    }
    pub fn encap_type(&self) -> bool {
        test_bit(self.raw, 14)
    }
    pub fn vxlan_port(&self) -> bool {
        test_bit(self.raw, 15)
    }
    pub fn cluster_heartbeat(&self) -> bool {
        test_bit(self.raw, 16)
    }

    pub fn set_mac_1(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 0, set);
    }

    pub fn set_mac_2(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 1, set);
    }

    pub fn set_vlan_id(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 2, set);
    }

    pub fn set_ether_type(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 3, set);
    }

    pub fn set_dscp(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 4, set);
    }

    pub fn set_transport_protocol(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 5, set);
    }

    pub fn set_ip_1(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 6, set);
    }

    pub fn set_ip_2(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 7, set);
    }

    pub fn set_ip_v6(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 8, set);
    }

    pub fn set_ip_1_prefix(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 9, set);
    }

    pub fn set_ip_2_prefix(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 10, set);
    }

    pub fn set_port_1(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 11, set);
    }

    pub fn set_port_2(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 12, set);
    }

    pub fn set_tcp_flags(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 13, set);
    }

    pub fn set_encap_type(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 14, set);
    }

    pub fn set_vxlan_port(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 15, set);
    }

    pub fn set_cluster_heartbeat(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 16, set);
    }
}

impl From<PktMonFilter> for PacketMonitorProtocolConstraint {
    fn from(filter: PktMonFilter) -> Self {
        let mut flags = Flags { raw: 0 };

        // Validate we're not mixing IPv4 and IPv6 addresses
        if let OptionPair::Both(ip_src, ip_dst) = filter.ip {
            match (ip_src, ip_dst) {
                (AnyIpCidr::V4(_), AnyIpCidr::V6(_)) | (AnyIpCidr::V6(_), AnyIpCidr::V4(_)) => {
                    // TODO: Should probably be a Result instead of panicking
                    panic!("Cannot mix IPv4 and IPv6 addresses");
                }

                _ => {}
            }
        }

        if matches!(
            filter.ip,
            OptionPair::Some(AnyIpCidr::V6(_)) | OptionPair::Both(AnyIpCidr::V6(_), _)
        ) {
            flags.set_ip_v6(true);
        }

        if filter.heartbeat {
            flags.set_cluster_heartbeat(true);
        }

        PacketMonitorProtocolConstraint {
            name: {
                let mut arr = [0u16; 64];

                let mut bytes = OsStr::new(&filter.name).encode_wide().collect::<Vec<u16>>();

                // Leave 1 byte for the NULL terminator
                if bytes.len() > 63 {
                    bytes = bytes[..63].to_vec();
                }

                arr[..bytes.len()].copy_from_slice(&bytes);
                arr
            },

            mac_1: {
                match filter.mac.first() {
                    Some(&mac) => {
                        flags.set_mac_1(true);
                        CMacAddr { addr: mac.0 }
                    }
                    None => CMacAddr { addr: [0; 6] },
                }
            },

            mac_2: {
                match filter.mac.second() {
                    Some(&mac) => {
                        flags.set_mac_2(true);
                        CMacAddr { addr: mac.0 }
                    }
                    None => CMacAddr { addr: [0; 6] },
                }
            },

            vlan_id: {
                if let Some(vlan_id) = filter.vlan {
                    flags.set_vlan_id(true);
                    vlan_id
                } else {
                    0
                }
            },

            ether_type: {
                if let Some(ether_type) = filter.data_link_protocol {
                    flags.set_ether_type(true);
                    ether_type.into()
                } else {
                    0
                }
            },

            dscp: {
                if let Some(dscp) = filter.dscp {
                    flags.set_dscp(true);
                    dscp as u16
                } else {
                    0
                }
            },

            transport_protocol: {
                if let Some(ref transport_protocol) = filter.transport_protocol {
                    flags.set_transport_protocol(true);
                    transport_protocol.into()
                } else {
                    0
                }
            },

            ip_1: {
                match filter.ip.first() {
                    Some(AnyIpCidr::Any) | None => CIPAddr {
                        v6: CIPv6Addr { addr: [0; 8] },
                    },
                    Some(&ip) => {
                        flags.set_ip_1(true);
                        CIPAddr::try_from(ip).unwrap()
                    }
                }
            },

            ip_2: {
                match filter.ip.second() {
                    Some(AnyIpCidr::Any) | None => CIPAddr {
                        v6: CIPv6Addr { addr: [0; 8] },
                    },
                    Some(&ip) => {
                        flags.set_ip_2(true);
                        CIPAddr::try_from(ip).unwrap()
                    }
                }
            },

            ip_1_prefix: {
                match filter.ip.first() {
                    Some(AnyIpCidr::Any) | None => 0,
                    Some(&ip) => {
                        flags.set_ip_1_prefix(ip.network_length().unwrap() > 0);
                        ip.network_length().unwrap()
                    }
                }
            },

            ip_2_prefix: {
                match filter.ip.second() {
                    Some(AnyIpCidr::Any) | None => 0,
                    Some(&ip) => {
                        flags.set_ip_2_prefix(ip.network_length().unwrap() > 0);
                        ip.network_length().unwrap()
                    }
                }
            },

            port_1: {
                match filter.port.first() {
                    Some(&port) => {
                        flags.set_port_1(true);
                        port
                    }
                    None => 0,
                }
            },

            port_2: {
                match filter.port.second() {
                    Some(&port) => {
                        flags.set_port_2(true);
                        port
                    }
                    None => 0,
                }
            },

            tcp_flags: {
                if let Some(TransportProtocol::FilteredTCP(tcp_flags)) = filter.transport_protocol {
                    flags.set_tcp_flags(true);
                    tcp_flags.iter().fold(0, |acc, flag| acc | u8::from(*flag))
                } else {
                    0
                }
            },

            encap_type: {
                if filter.encapsulation.is_on() {
                    flags.set_encap_type(true);
                    0xFF
                } else {
                    0
                }
            },

            vxlan_port: {
                if let Encapsulation::On(Some(vxlan_port)) = filter.encapsulation {
                    flags.set_vxlan_port(true);
                    vxlan_port.0
                } else {
                    0
                }
            },

            flags, // Set last to ensure effects are applied

            packets: 0,
            bytes: 0,
        }
    }
}
