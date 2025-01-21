use std::{ffi::OsStr, fmt::Debug, os::windows::ffi::OsStrExt};

use cidr::AnyIpCidr;

use crate::filter::{Encapsulation, OptionPair, PktMonFilter, TransportProtocol};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CPktMonFilter {
    /*
        NOTE: When two MACs, IPs, or ports are specified, the filter
           matches packets that contain both. It will not distinguish between source
           or destination for this purpose.
    */

    // Offset 0x00-0x7F: Name/Description field (128 bytes)
    pub name: [u8; 128],          // 128 bytes (doubled from 64 for wide chars) UTF-16LE

    // Offset 0x80: Control flags (32-bit)
    pub flags: Flags,             // Using a separate struct for bitfields

    // Offset 0x84: MAC addresses (12 bytes)
    pub mac_src: CMacAddr,         // Source MAC
    pub mac_dst: CMacAddr,         // Destination MAC

    // Offset 0x90: VLAN ID
    pub vlan: u16,

    // Offset 0x92: EtherType/Protocol
    pub protocol: u16,

    // Offset 0x94: DSCP
    pub dscp: u16, // Max value is 0x3F

    // Offset 0x96: Transport protocol
    pub transport_proto: u16,

    // Offset 0x98: IP source address
    pub ip_src: CIPAddr,

    // Offset 0xA8: IP destination address
    pub ip_dst: CIPAddr,

    // Offset 0xB8: IP source prefix
    pub ip_src_prefix: u8,

    // Offset 0xB9: IP destination prefix
    pub ip_dst_prefix: u8,

    // Offset 0xBA: Ports
    pub port_src: u16,
    pub port_dst: u16,

    // Offset 0xBE: TCP flags
    pub tcp_flags: u8,

    _padding: u8,

    // Offset 0xC0: Encapsulation
    pub encapsulation: u32,

    // Offset 0xC4: VXLAN port
    pub vxlan_port: u16,

    // Offset 0xC6 - 0xD8: Reserved for future use
    _reserved: [u8; 18],
}

impl CPktMonFilter {
    pub fn as_bytes(&self) -> [u8; 108*2] {
        unsafe { std::mem::transmute::<CPktMonFilter, [u8; 108*2]>(*self) }
    }
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

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Flags {
    pub raw: u32,
}

impl Debug for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Flags {{ mac_src: {}, mac_dst: {}, vlan_id: {}, data_link_protocol: {}, dscp: {}, transport_protocol: {}, ip_src: {}, ip_dst: {}, ip_v6: {}, ip_src_prefix: {}, ip_dst_prefix: {}, port_src: {}, port_dst: {}, tcp_flags: {}, encapsulation: {}, vxlan_port: {}, heartbeat: {} }}", 
            self.mac_src(),
            self.mac_dst(),
            self.vlan_id(),
            self.data_link_protocol(),
            self.dscp(),
            self.transport_protocol(),
            self.ip_src(),
            self.ip_dst(),
            self.ip_v6(),
            self.ip_src_prefix(),
            self.ip_dst_prefix(),
            self.port_src(),
            self.port_dst(),
            self.tcp_flags(),
            self.encapsulation(),
            self.vxlan_port(),
            self.heartbeat()
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
    pub fn mac_src(&self)            -> bool { test_bit(self.raw, 0) }
    pub fn mac_dst(&self)            -> bool { test_bit(self.raw, 1) }
    pub fn vlan_id(&self)            -> bool { test_bit(self.raw, 2) }
    pub fn data_link_protocol(&self) -> bool { test_bit(self.raw, 3) }
    pub fn dscp(&self)               -> bool { test_bit(self.raw, 4) }
    pub fn transport_protocol(&self) -> bool { test_bit(self.raw, 5) }
    pub fn ip_src(&self)             -> bool { test_bit(self.raw, 6) }
    pub fn ip_dst(&self)             -> bool { test_bit(self.raw, 7) }
    pub fn ip_v6(&self)              -> bool { test_bit(self.raw, 8) }
    pub fn ip_src_prefix(&self)      -> bool { test_bit(self.raw, 9) }
    pub fn ip_dst_prefix(&self)      -> bool { test_bit(self.raw, 10) }
    pub fn port_src(&self)           -> bool { test_bit(self.raw, 11) }
    pub fn port_dst(&self)           -> bool { test_bit(self.raw, 12) }
    pub fn tcp_flags(&self)          -> bool { test_bit(self.raw, 13) }
    pub fn encapsulation(&self)      -> bool { test_bit(self.raw, 14) }
    pub fn vxlan_port(&self)         -> bool { test_bit(self.raw, 15) }
    pub fn heartbeat(&self)          -> bool { test_bit(self.raw, 16) }

    pub fn set_mac_src(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 0, set);
    }

    pub fn set_mac_dst(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 1, set);
    }

    pub fn set_vlan_id(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 2, set);
    }

    pub fn set_data_link_protocol(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 3, set);
    }

    pub fn set_dscp(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 4, set);
    }

    pub fn set_transport_protocol(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 5, set);
    }

    pub fn set_ip_src(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 6, set);
    }

    pub fn set_ip_dst(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 7, set);
    }

    pub fn set_ip_v6(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 8, set);
    }

    pub fn set_ip_src_prefix(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 9, set);
    }

    pub fn set_ip_dst_prefix(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 10, set);
    }

    pub fn set_port_src(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 11, set);
    }

    pub fn set_port_dst(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 12, set);
    }

    pub fn set_tcp_flags(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 13, set);
    }

    pub fn set_encapsulation(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 14, set);
    }

    pub fn set_vxlan_port(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 15, set);
    }

    pub fn set_heartbeat(&mut self, set: bool) {
        self.raw = set_bit(self.raw, 16, set);
    }
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

impl From<PktMonFilter> for CPktMonFilter {
    fn from(filter: PktMonFilter) -> Self {
        let mut flags = Flags { raw: 0 };

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

        if matches!(filter.ip, OptionPair::Some(AnyIpCidr::V6(_)) | OptionPair::Both(AnyIpCidr::V6(_), _)) {
            flags.set_ip_v6(true);
        }

        if filter.heartbeat {
            flags.set_heartbeat(true);
        }

        CPktMonFilter {
            name: {
                let mut arr = [0u8; 128];
                
                let bytes = OsStr::new(&filter.name)
                    .encode_wide()
                    .flat_map(|x| x.to_le_bytes())
                    .collect::<Vec<u8>>();

                arr[..bytes.len()].copy_from_slice(&bytes);
                arr
            },

            mac_src: {
                if let Some(mac_src) = filter.mac_src {
                    flags.set_mac_src(true);
                    CMacAddr { addr: mac_src.0 }
                } else {
                    CMacAddr { addr: [0; 6] }
                }
            },

            mac_dst: {
                if let Some(mac_dst) = filter.mac_dst {
                    flags.set_mac_dst(true);
                    CMacAddr { addr: mac_dst.0 }
                } else {
                    CMacAddr { addr: [0; 6] }
                }
            },

            vlan: {
                if let Some(vlan) = filter.vlan {
                    flags.set_vlan_id(true);
                    vlan
                } else {
                    0
                }
            },
            
            protocol: {
                if let Some(protocol) = filter.data_link_protocol {
                    flags.set_data_link_protocol(true);
                    protocol.into()
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

            transport_proto: {
                if let Some(ref transport_proto) = filter.transport_protocol {
                    flags.set_transport_protocol(true);
                    transport_proto.into()
                } else {
                    0
                }
            },

            ip_src: {
                // if !filter.ip_src.is_any() {
                //     flags.set_ip_src(true);
                //     CIPAddr::try_from(filter.ip_src).unwrap()
                // } else {
                //     CIPAddr { v6: CIPv6Addr { addr: [0; 8] } }
                // }
                match filter.ip.first() {
                    Some(AnyIpCidr::Any) | None => CIPAddr { v6: CIPv6Addr { addr: [0; 8] } },
                    Some(&ip) => {
                        flags.set_ip_src(true);
                        CIPAddr::try_from(ip).unwrap()
                    }
                }
            },

            ip_dst: {
                // if !filter.ip_dst.is_any() {
                //     flags.set_ip_dst(true);
                //     CIPAddr::try_from(filter.ip_dst).unwrap()
                // } else {
                //     CIPAddr { v6: CIPv6Addr { addr: [0; 8] } }
                // }
                match filter.ip.second() {
                    Some(AnyIpCidr::Any) | None => CIPAddr { v6: CIPv6Addr { addr: [0; 8] } },
                    Some(&ip) => {
                        flags.set_ip_dst(true);
                        CIPAddr::try_from(ip).unwrap()
                    }
                }
            },

            ip_src_prefix: {
                // if let Some(prefix) = filter.ip_src.network_length() {
                //     flags.set_ip_src_prefix(prefix > 0);
                //     prefix
                // } else {
                //     0
                // }
                match filter.ip.first() {
                    Some(AnyIpCidr::Any) | None => 0,
                    Some(&ip) => {
                        flags.set_ip_src_prefix(ip.network_length().unwrap() > 0);
                        ip.network_length().unwrap()
                    }
                }
            },

            ip_dst_prefix: {
                // if let Some(prefix) = filter.ip_dst.network_length() {
                //     flags.set_ip_dst_prefix(prefix > 0);
                //     prefix
                // } else {
                //     0
                // }
                match filter.ip.second() {
                    Some(AnyIpCidr::Any) | None => 0,
                    Some(&ip) => {
                        flags.set_ip_dst_prefix(ip.network_length().unwrap() > 0);
                        ip.network_length().unwrap()
                    }
                }
            },

            port_src: {
                // if let Some(port_src) = filter.port_src {
                //     flags.set_port_src(true);
                //     port_src
                // } else {
                //     0
                // }
                match filter.port.first() {
                    Some(&port) => {
                        flags.set_port_src(true);
                        port
                    }
                    None => 0,
                }
            },

            port_dst: {
                // if letSome(port_dst) = filter.port_dst {
                //     flags.set_port_dst(true);
                //     port_dst
                // } else {
                //     0
                // }
                match filter.port.second() {
                    Some(&port) => {
                        flags.set_port_dst(true);
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

            encapsulation: {
                if filter.encapsulation.is_on() {
                    flags.set_encapsulation(true);
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

            _padding: 0,
            _reserved: [0; 18],

            flags, // Set last to ensure effects are applied
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use std::str::FromStr;

    use cidr::Ipv4Cidr;
    use utf16string::{WString, LE};

    use crate::filter::{TCPFlag, TransportProtocol, VXLANPort};

    use super::*;

    impl CPktMonFilter {
        pub unsafe fn from_bytes_unchecked(data: [u16; 108]) -> Self {
            std::mem::transmute::<[u16; 108], CPktMonFilter>(data)
        }

        pub fn as_words(&self) -> [u16; 108] {
            unsafe { std::mem::transmute::<CPktMonFilter, [u16; 108]>(*self) }
        }

        pub fn name(&self) -> WString<LE> {
            let mut bytes: Vec<u8> = self.name.chunks(2)
                .take_while(|&x| x[0] != 0 || x[1] != 0) // Stop at NULL terminator
                .flat_map(|x| x.to_vec())
                .collect();

            if bytes.len() % 2 != 0 {
                bytes.push(0);
            }

            WString::from_utf16le(bytes).expect("Invalid UTF-16LE string")
        }
    }

    // TCP flag constants
    const FIN: u8 = 0b00000001;
    const SYN: u8 = 0b00000010;
    const RST: u8 = 0b00000100;
    const PSH: u8 = 0b00001000;
    const ACK: u8 = 0b00010000;
    const URG: u8 = 0b00100000;
    const ECE: u8 = 0b01000000;
    const CWR: u8 = 0b10000000;

    // Filter Flags
    const MAC_SRC            : u32 = 0b00000000000000000000000000000001;
    const MAC_DST            : u32 = 0b00000000000000000000000000000010;
    const VLAN_ID            : u32 = 0b00000000000000000000000000000100;
    const DATA_LINK_PROTOCOL : u32 = 0b00000000000000000000000000001000;
    const DSCP               : u32 = 0b00000000000000000000000000010000;
    const TRANSPORT_PROTOCOL : u32 = 0b00000000000000000000000000100000;
    const IP_SRC             : u32 = 0b00000000000000000000000001000000;
    const IP_DST             : u32 = 0b00000000000000000000000010000000;
    const IP_V6              : u32 = 0b00000000000000000000000100000000;
    const IP_SRC_PREFIX      : u32 = 0b00000000000000000000001000000000;
    const IP_DST_PREFIX      : u32 = 0b00000000000000000000010000000000;
    const PORT_SRC           : u32 = 0b00000000000000000000100000000000;
    const PORT_DST           : u32 = 0b00000000000000000001000000000000;
    const TCP_FLAGS          : u32 = 0b00000000000000000010000000000000;
    const ENCAPSULATION      : u32 = 0b00000000000000000100000000000000;
    const VXLAN_PORT         : u32 = 0b00000000000000001000000000000000;
    const HEARTBEAT          : u32 = 0b00000000000000010000000000000000;

    #[test]
    fn test_bit_function() {
        assert!(test_bit(0b00000001, 0));
        assert!(test_bit(0b00000010, 1));
        assert!(test_bit(0b00000100, 2));
    }

    #[test]
    fn sizeof_filter() {
        assert_eq!(std::mem::size_of::<CPktMonFilter>(), 0xD8);
    }

    #[test]
    fn field_offsets() {
        assert_eq!(std::mem::offset_of!(CPktMonFilter, name), 0x00);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, flags), 0x80);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, mac_src), 0x84);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, mac_dst), 0x8A);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, vlan), 0x90);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, protocol), 0x92);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, dscp), 0x94);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, transport_proto), 0x96);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, ip_src), 0x98);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, ip_dst), 0xA8);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, ip_src_prefix), 0xB8);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, ip_dst_prefix), 0xB9);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, port_src), 0xBA);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, port_dst), 0xBC);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, tcp_flags), 0xBE);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, _padding), 0xBF);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, encapsulation), 0xC0);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, vxlan_port), 0xC4);
        assert_eq!(std::mem::offset_of!(CPktMonFilter, _reserved), 0xC6);
    }

    const DATA: [u16; 108] = [
        0x0052, 0x0051, 0x0041, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0xfa60, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0006, 0x2301, 0x0045, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000, 0x0018, 0x5b05, 0x5b06, 0x0025,
        0x00ff, 0x0000, 0xffff, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0000, 0x0000
    ];

    #[test]
    fn deserialize() {
        let filter = unsafe { CPktMonFilter::from_bytes_unchecked(DATA) };
        println!("{:?}", filter);

        assert_eq!(WString::from("RQA"), filter.name());

        assert_eq!(Flags { 
            raw: IP_SRC | IP_SRC_PREFIX | PORT_SRC | PORT_DST | TRANSPORT_PROTOCOL | TCP_FLAGS | ENCAPSULATION | VXLAN_PORT
        }, filter.flags);

        assert_eq!(CIPv4Addr { addr: [1, 35, 69, 0], pad: [0; 12] }, unsafe { filter.ip_src.v4 });
        assert_eq!(24, filter.ip_src_prefix);

        assert_eq!(23301, filter.port_src);
        assert_eq!(23302, filter.port_dst);

        assert_eq!(u16::from(&TransportProtocol::TCP), filter.transport_proto);
        assert_eq!(FIN | RST | URG, filter.tcp_flags);

        assert_eq!(0xFF, filter.encapsulation);
        assert_eq!(0xFFFF, filter.vxlan_port);
    }

    #[test]
    fn serialize() {
        let filter = PktMonFilter {
            name: "RQA".to_string(),
            
            // ip_src: AnyIpCidr::V4(Ipv4Cidr::from_str("1.35.69.0/24").unwrap()),
            ip: AnyIpCidr::V4(Ipv4Cidr::from_str("1.35.69.0/24").unwrap()).into(),

            // port_src: Some(23301),
            // port_dst: Some(23302),
            port: (23301, 23302).into(),
            // port: None.into(),

            transport_protocol: Some(TransportProtocol::FilteredTCP(vec![TCPFlag::FIN, TCPFlag::RST, TCPFlag::URG])),

            encapsulation: Encapsulation::On(Some(VXLANPort(0xFFFF))),

            ..Default::default()
        };
        
        assert_eq!(DATA, CPktMonFilter::from(filter).as_words());
    }
}

