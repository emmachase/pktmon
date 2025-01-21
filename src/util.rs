macro_rules! s_with_len {
    ($i:ident, $i_len:ident, $s:literal) => {
        const $i: windows::core::PCSTR = windows::core::PCSTR::from_raw(::std::concat!($s, '\0').as_ptr());
        const $i_len: usize = $s.len() + 1;
    };
}

pub(crate) use s_with_len;
