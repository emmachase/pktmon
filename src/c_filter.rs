use std::{ffi::OsStr, fmt::Debug, os::windows::ffi::OsStrExt};

use cidr::AnyIpCidr;

use crate::filter::{Encapsulation, OptionPair, PktMonFilter, TransportProtocol};

/*
 * NOTE: When two MACs, IPs, or ports are specified, the filter
 *  matches packets that contain both. It will not distinguish between source
 *  or destination for this purpose.
 */
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CPktMonUserFilter {
    /// Structure size (195 or 200), we always use 200
    pub size: u16,

    /// Name (128 bytes as wchar_t is 2 bytes)
    /// Offset 2: Takes us to offset 130
    pub name: [u8; 128],

    /// Source MAC (6 bytes)
    /// Offset 130
    pub mac_src: CMacAddr,

    /// Destination MAC (6 bytes)
    /// Offset 136
    pub mac_dst: CMacAddr,

    /// VLAN ID
    /// Offset 142
    pub vlan: u16,

    /// EtherType/Protocol
    /// Offset 144
    pub protocol: u16,

    /// Transport protocol
    /// Offset 146
    pub transport_proto: u8,

    /// IP version flag
    /// Offset 147
    pub ip_v6: u8,

    /// Padding to align to offset 152
    _padding1: [u8; 4],

    /// IP source address (16 bytes)
    /// Offset 152
    pub ip_src: CIPAddr,

    /// IP destination address (16 bytes)
    /// Offset 168
    pub ip_dst: CIPAddr,

    /// IP source prefix
    /// Offset 184
    pub ip_src_prefix: u8,

    /// IP destination prefix
    /// Offset 185
    pub ip_dst_prefix: u8,

    /// Source port
    /// Offset 186
    pub port_src: u16,

    /// Destination port
    /// Offset 188
    pub port_dst: u16,

    /// TCP flags
    /// Offset 190
    pub tcp_flags: u8,

    /// Encapsulation
    /// Offset 191
    pub encapsulation: u8,

    /// VXLAN port
    /// Offset 192
    pub vxlan_port: u16,

    /// Heartbeat
    /// Offset 194
    pub heartbeat: u8,

    /// Padding
    /// Offset 195
    _padding2: u8,

    /// DSCP Value (only in 200 byte version)
    /// Offset 196
    pub dscp: u16,

    /// Padding
    /// Offset 198
    _padding3: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CMacAddr {
    pub addr: [u8; 6],
}

#[repr(C)]
#[derive(Copy, Clone, Eq)]
pub union CIPAddr {
    pub v4: CIPv4Addr,
    pub v6: CIPv6Addr,
}

impl Debug for CIPAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            write!(f, "IpAddr({:?} or {:?})", self.v4, self.v6)
        }
    }
}

impl PartialEq for CIPAddr {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            // No need to check v4 because they overlap in memory
            self.v6 == other.v6
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CIPv4Addr {
    pub addr: [u8; 4],
    pub pad: [u8; 12],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CIPv6Addr {
    pub addr: [u16; 8]
}

impl TryFrom<AnyIpCidr> for CIPAddr {
    type Error = ();

    fn try_from(ip: AnyIpCidr) -> Result<Self, Self::Error> {
        match ip {
            AnyIpCidr::Any => Err(()),
            AnyIpCidr::V4(ip) => Ok(CIPAddr { v4: CIPv4Addr { addr: ip.first_address().octets(), pad: [0; 12] } }),
            AnyIpCidr::V6(ip) => Ok(CIPAddr { v6: CIPv6Addr { addr: ip.first_address().segments() } }),
        }
    }
}

impl From<PktMonFilter> for CPktMonUserFilter {
    fn from(filter: PktMonFilter) -> Self {
        // Validate we're not mixing IPv4 and IPv6 addresses
        if let OptionPair::Both(ip_src, ip_dst) = filter.ip {
            match (ip_src, ip_dst) {
                (AnyIpCidr::V4(_), AnyIpCidr::V6(_)) |
                (AnyIpCidr::V6(_), AnyIpCidr::V4(_)) => {
                    // TODO: Should probably be a Result instead of panicking
                    panic!("Cannot mix IPv4 and IPv6 addresses");
                }

                _ => {}
            }
        }

        let ip_version = if matches!(filter.ip, OptionPair::Some(AnyIpCidr::V6(_)) | OptionPair::Both(AnyIpCidr::V6(_), _)) {
            1
        } else {
            0
        };

        CPktMonUserFilter {
            size: 200,

            name: {
                let mut arr = [0u8; 128];
                
                let mut bytes = OsStr::new(&filter.name)
                    .encode_wide()
                    .flat_map(|x| x.to_le_bytes())
                    .collect::<Vec<u8>>();

                // Leave 2 bytes for the NULL terminator
                if bytes.len() > 126 {
                    bytes = bytes[..126].to_vec();
                }

                arr[..bytes.len()].copy_from_slice(&bytes);
                arr
            },

            mac_src: {
                match filter.mac.first() {
                    Some(&mac) => CMacAddr { addr: mac.0 },
                    None => CMacAddr { addr: [0; 6] }
                }
            },

            mac_dst: {
                match filter.mac.second() {
                    Some(&mac) => CMacAddr { addr: mac.0 },
                    None => CMacAddr { addr: [0; 6] }
                }
            },

            vlan: {
                if let Some(vlan) = filter.vlan {
                    vlan
                } else {
                    0
                }
            },
            
            protocol: {
                if let Some(protocol) = filter.data_link_protocol {
                    protocol.into()
                } else {
                    0
                }
            },

            transport_proto: {
                if let Some(ref transport_proto) = filter.transport_protocol {
                    transport_proto.into()
                } else {
                    0
                }
            },

            ip_v6: ip_version,

            ip_src: {
                match filter.ip.first() {
                    Some(AnyIpCidr::Any) | None => CIPAddr { v6: CIPv6Addr { addr: [0; 8] } },
                    Some(&ip) => CIPAddr::try_from(ip).unwrap()
                }
            },

            ip_dst: {
                match filter.ip.second() {
                    Some(AnyIpCidr::Any) | None => CIPAddr { v6: CIPv6Addr { addr: [0; 8] } },
                    Some(&ip) => CIPAddr::try_from(ip).unwrap()
                }
            },

            ip_src_prefix: {
                match filter.ip.first() {
                    Some(AnyIpCidr::Any) | None => 0,
                    Some(&ip) => ip.network_length().unwrap()
                }
            },

            ip_dst_prefix: {
                match filter.ip.second() {
                    Some(AnyIpCidr::Any) | None => 0,
                    Some(&ip) => ip.network_length().unwrap()
                }
            },

            port_src: {
                match filter.port.first() {
                    Some(&port) => port,
                    None => 0,
                }
            },

            port_dst: {
                match filter.port.second() {
                    Some(&port) => port,
                    None => 0,
                }
            },

            tcp_flags: {
                if let Some(TransportProtocol::FilteredTCP(tcp_flags)) = filter.transport_protocol {
                    tcp_flags.iter().fold(0, |acc, flag| acc | u8::from(*flag))
                } else {
                    0
                }
            },

            encapsulation: {
                if filter.encapsulation.is_on() {
                    0xFF
                } else {
                    0
                }
            },
            
            vxlan_port: {
                if let Encapsulation::On(Some(vxlan_port)) = filter.encapsulation {
                    vxlan_port.0
                } else {
                    0
                }
            },

            heartbeat: filter.heartbeat as u8,
            
            dscp: {
                if let Some(dscp) = filter.dscp {
                    dscp as u16
                } else {
                    0
                }
            },

            _padding1: [0; 4],
            _padding2: 0,
            _padding3: [0; 2],
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    #[test]
    fn sizeof_user_filter() {
        assert_eq!(std::mem::size_of::<CPktMonUserFilter>(), 0xC8);
    }

    #[test]
    fn field_offsets_user_filter() {
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, size), 0x00);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, name), 0x02);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, mac_src), 0x82);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, mac_dst), 0x88);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, vlan), 0x8E);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, protocol), 0x90);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, transport_proto), 0x92);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, ip_v6), 0x93);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, _padding1), 0x94);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, ip_src), 0x98);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, ip_dst), 0xA8);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, ip_src_prefix), 0xB8);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, ip_dst_prefix), 0xB9);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, port_src), 0xBA);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, port_dst), 0xBC);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, tcp_flags), 0xBE);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, encapsulation), 0xBF);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, vxlan_port), 0xC0);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, heartbeat), 0xC2);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, _padding2), 0xC3);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, dscp), 0xC4);
        assert_eq!(std::mem::offset_of!(CPktMonUserFilter, _padding3), 0xC6);
    }
}

