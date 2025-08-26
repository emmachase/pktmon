use cidr::AnyIpCidr;
use std::fmt::Debug;

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
        unsafe { write!(f, "IpAddr({:?} or {:?})", self.v4, self.v6) }
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
    pub addr: [u16; 8],
}

impl TryFrom<AnyIpCidr> for CIPAddr {
    type Error = ();

    fn try_from(ip: AnyIpCidr) -> Result<Self, Self::Error> {
        match ip {
            AnyIpCidr::Any => Err(()),
            AnyIpCidr::V4(ip) => Ok(CIPAddr {
                v4: CIPv4Addr {
                    addr: ip.first_address().octets(),
                    pad: [0; 12],
                },
            }),
            AnyIpCidr::V6(ip) => Ok(CIPAddr {
                v6: CIPv6Addr {
                    addr: ip.first_address().segments(),
                },
            }),
        }
    }
}
