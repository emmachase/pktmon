use std::{num::ParseIntError, str::FromStr};

use cidr::AnyIpCidr;

///
/// NOTE: When two MACs, IPs, or ports are specified, the filter
///  matches packets that contain both. It will not distinguish between source
///  or destination for this purpose.
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PktMonFilter {
    /// Name of the filter.
    ///
    /// Max length is 63 characters.
    /// Driver will truncate to 63 characters if longer.
    pub name: String,

    /// Match by source MAC address.
    ///
    /// See [`OptionPair`] for more information.
    pub mac: OptionPair<MacAddr>,

    /// Match by source IP address.
    ///
    /// See [`OptionPair`] for more information.
    pub ip: OptionPair<AnyIpCidr>,

    /// Match by source port.
    ///
    /// See [`OptionPair`] for more information.
    pub port: OptionPair<u16>,

    /// Match by the 6-bit Differentiated Services Code Point (DSCP) field.
    pub dscp: Option<u8>,

    /// Match by VLAN Id (VID) in the 802.1Q header.
    pub vlan: Option<u16>,

    /// Match by data link (layer 2) protocol. Can be IPv4, IPv6, ARP, or a protocol number.
    pub data_link_protocol: Option<DataLinkProtocol>,

    /// Match by transport (layer 4) protocol. Can be TCP, UDP, ICMP, ICMPv6, or a protocol number.
    ///  To further filter TCP packets, an optional list of TCP flags to match can
    ///  be provided. Supported flags are FIN, SYN, RST, PSH, ACK, URG, ECE, and CWR.
    pub transport_protocol: Option<TransportProtocol>,

    /// Apply above filtering parameters to both inner and outer encapsulation headers.
    ///  Supported encapsulation methods are VXLAN, GRE, NVGRE, and IP-in-IP.
    ///  Custom VXLAN port is optional, and defaults to 4789.
    pub encapsulation: Encapsulation,

    /// If true, match RCP heartbeat messages over UDP port 3343.
    pub heartbeat: bool,
}

impl Default for PktMonFilter {
    fn default() -> Self {
        Self {
            name: "Unamed Filter".to_owned(),
            mac: OptionPair::None,
            ip: OptionPair::None,
            port: OptionPair::None,
            dscp: None,
            vlan: None,
            data_link_protocol: None,
            transport_protocol: None,
            encapsulation: Encapsulation::Off,
            heartbeat: false,
        }
    }
}

///
/// Represents None, Some, or Both values.
/// If Both are present, the filter will only match packets that contain both values, NOT either.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionPair<T> {
    None,
    Some(T),
    Both(T, T),
}

impl<T> OptionPair<T> {
    pub fn first(&self) -> Option<&T> {
        match self {
            OptionPair::None => None,
            OptionPair::Some(value) | OptionPair::Both(value, _) => Some(value),
        }
    }

    pub fn second(&self) -> Option<&T> {
        match self {
            OptionPair::None | OptionPair::Some(_) => None,
            OptionPair::Both(_, value) => Some(value),
        }
    }
}

impl<T> Default for OptionPair<T> {
    fn default() -> Self {
        OptionPair::None
    }
}

impl<T> From<T> for OptionPair<T> {
    fn from(value: T) -> Self {
        OptionPair::Some(value)
    }
}

impl<T> From<(T, T)> for OptionPair<T> {
    fn from(value: (T, T)) -> Self {
        OptionPair::Both(value.0, value.1)
    }
}

impl<T> From<Option<T>> for OptionPair<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => OptionPair::Some(value),
            None => OptionPair::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl FromStr for MacAddr {
    type Err = ParseIntError;

    // AA:BB:CC:DD:EE:FF
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: Check for valid format
        let mut addr = [0; 6];
        let mut i = 0;
        for part in s.split(':') {
            addr[i] = u8::from_str_radix(part, 16)?;
            i += 1;
        }
        Ok(MacAddr(addr))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(addr: [u8; 6]) -> Self {
        MacAddr(addr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataLinkProtocol {
    IPV4,
    IPV6,
    ARP,

    Custom(u16),
}

impl From<u16> for DataLinkProtocol {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => DataLinkProtocol::IPV4,
            0x86DD => DataLinkProtocol::IPV6,
            0x0806 => DataLinkProtocol::ARP,
            _ => DataLinkProtocol::Custom(value),
        }
    }
}

impl From<DataLinkProtocol> for u16 {
    fn from(value: DataLinkProtocol) -> Self {
        match value {
            DataLinkProtocol::IPV4 => 0x0800,
            DataLinkProtocol::IPV6 => 0x86DD,
            DataLinkProtocol::ARP => 0x0806,
            DataLinkProtocol::Custom(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    TCP,
    FilteredTCP(Vec<TCPFlag>),
    UDP,
    ICMP,
    ICMPV6,

    Custom(u8),
}

impl From<u8> for TransportProtocol {
    fn from(value: u8) -> Self {
        match value {
            6 => TransportProtocol::TCP,
            17 => TransportProtocol::UDP,
            1 => TransportProtocol::ICMP,
            58 => TransportProtocol::ICMPV6,
            _ => TransportProtocol::Custom(value),
        }
    }
}

impl From<&TransportProtocol> for u8 {
    fn from(value: &TransportProtocol) -> Self {
        match value {
            TransportProtocol::TCP => 6,
            TransportProtocol::FilteredTCP(_flags) => 6,
            TransportProtocol::UDP => 17,
            TransportProtocol::ICMP => 1,
            TransportProtocol::ICMPV6 => 58,
            TransportProtocol::Custom(value) => *value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TCPFlag {
    SYN,
    ACK,
    FIN,
    RST,
    PSH,
    URG,
    ECE,
    CWR,
}

impl From<TCPFlag> for u8 {
    fn from(value: TCPFlag) -> Self {
        match value {
            TCPFlag::FIN => 0b00000001,
            TCPFlag::SYN => 0b00000010,
            TCPFlag::RST => 0b00000100,
            TCPFlag::PSH => 0b00001000,
            TCPFlag::ACK => 0b00010000,
            TCPFlag::URG => 0b00100000,
            TCPFlag::ECE => 0b01000000,
            TCPFlag::CWR => 0b10000000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encapsulation {
    Off,
    On(Option<VXLANPort>),
}

impl Encapsulation {
    pub fn is_on(&self) -> bool {
        matches!(self, Encapsulation::On(_))
    }

    pub fn is_off(&self) -> bool {
        matches!(self, Encapsulation::Off)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VXLANPort(pub u16);

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn sandbox() {
        let filter = PktMonFilter {
            ip: AnyIpCidr::new_host(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).into(),
            ..Default::default()
        };

        println!("{:?}", filter);
    }
}
