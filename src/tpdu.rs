//! COTP class 0 TPDUs, ISO 8073 as RFC 1006 profiles it: the four that a
//! connection needs and nothing the class does not use.
//!
//! Every TPDU opens with a length indicator — the header's length, itself
//! excluded — and a code byte. Connect request and confirm carry a variable
//! part of `code length value` parameters, of which three matter here: the
//! TPDU size (0xC0), the calling TSAP (0xC1) and the called TSAP (0xC2). Data
//! carries one byte whose top bit says whether the segment ends the message.

use transport::error::{Result, protocol_error};

/// The TPDU size code proposed by default: 2^10, 1024 bytes.
pub const DEFAULT_SIZE_CODE: u8 = 10;
/// The largest size code class 0 negotiates: 2^13, 8192 bytes.
pub const MAX_SIZE_CODE: u8 = 13;
/// The smallest: 2^7, 128 bytes.
pub const MIN_SIZE_CODE: u8 = 7;

const CR: u8 = 0xE0;
const CC: u8 = 0xD0;
const DT: u8 = 0xF0;
const DR: u8 = 0x80;
const PARAM_SIZE: u8 = 0xC0;
const PARAM_SRC_TSAP: u8 = 0xC1;
const PARAM_DST_TSAP: u8 = 0xC2;

/// One transport protocol data unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tpdu {
    /// CR: the caller names both TSAPs and proposes a size.
    ConnectRequest(Connect),
    /// CC: the called side echoes the TSAPs and settles the size.
    ConnectConfirm(Connect),
    /// DT: one segment of a message; `last` is the EOT bit.
    Data { last: bool, payload: Vec<u8> },
    /// DR: either side ends the connection.
    Disconnect { reason: u8 },
}

/// What CR and CC carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connect {
    pub src_ref: u16,
    pub dst_ref: u16,
    /// The size code: the TPDU may be 2^code bytes.
    pub size_code: u8,
    pub src_tsap: Vec<u8>,
    pub dst_tsap: Vec<u8>,
}

/// The largest TPDU a size code allows.
#[must_use]
pub fn size_of(code: u8) -> usize {
    1usize << code.clamp(MIN_SIZE_CODE, MAX_SIZE_CODE)
}

/// `tpdu` as bytes on the wire.
#[must_use]
pub fn encode(tpdu: &Tpdu) -> Vec<u8> {
    match tpdu {
        Tpdu::ConnectRequest(connect) => encode_connect(CR, connect),
        Tpdu::ConnectConfirm(connect) => encode_connect(CC, connect),
        Tpdu::Data { last, payload } => {
            let mut out = Vec::with_capacity(3 + payload.len());
            out.extend_from_slice(&[2, DT, if *last { 0x80 } else { 0x00 }]);
            out.extend_from_slice(payload);
            out
        }
        Tpdu::Disconnect { reason } => vec![6, DR, 0, 0, 0, 0, *reason],
    }
}

fn encode_connect(code: u8, connect: &Connect) -> Vec<u8> {
    let mut out = vec![0, code];
    out.extend_from_slice(&connect.dst_ref.to_be_bytes());
    out.extend_from_slice(&connect.src_ref.to_be_bytes());
    out.push(0);
    out.extend_from_slice(&[PARAM_SIZE, 1, connect.size_code]);
    for (param, tsap) in [
        (PARAM_SRC_TSAP, &connect.src_tsap),
        (PARAM_DST_TSAP, &connect.dst_tsap),
    ] {
        let tsap = &tsap[..tsap.len().min(usize::from(u8::MAX))];
        out.push(param);
        out.push(u8::try_from(tsap.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(tsap);
    }
    out[0] = u8::try_from(out.len() - 1).unwrap_or(u8::MAX);
    out
}

/// Read one TPDU.
///
/// # Errors
/// A length indicator past the end, a code class 0 does not use, or a
/// parameter that runs off the header.
pub fn decode(bytes: &[u8]) -> Result<Tpdu> {
    let (&li, rest) = bytes
        .split_first()
        .ok_or_else(|| protocol_error("an empty TPDU"))?;
    let li = usize::from(li);
    if li > rest.len() || li == 0 {
        return Err(protocol_error("a TPDU length indicator past the end"));
    }
    let (header, payload) = rest.split_at(li);
    match header[0] & 0xF0 {
        CR => decode_connect(header).map(Tpdu::ConnectRequest),
        CC => decode_connect(header).map(Tpdu::ConnectConfirm),
        DT => {
            if header.len() != 2 {
                return Err(protocol_error("a class 0 DT whose header is not two bytes"));
            }
            Ok(Tpdu::Data {
                last: header[1] & 0x80 != 0,
                payload: payload.to_vec(),
            })
        }
        DR => Ok(Tpdu::Disconnect {
            reason: header.get(5).copied().unwrap_or(0),
        }),
        other => Err(protocol_error(format!(
            "TPDU code {other:#04x} is not one class 0 uses"
        ))),
    }
}

fn decode_connect(header: &[u8]) -> Result<Connect> {
    if header.len() < 6 {
        return Err(protocol_error("a connect TPDU shorter than its fixed part"));
    }
    let mut connect = Connect {
        dst_ref: u16::from_be_bytes([header[1], header[2]]),
        src_ref: u16::from_be_bytes([header[3], header[4]]),
        size_code: DEFAULT_SIZE_CODE,
        src_tsap: Vec::new(),
        dst_tsap: Vec::new(),
    };
    if header[5] & 0xF0 != 0 {
        return Err(protocol_error("a connect for a class other than 0"));
    }
    let mut at = 6;
    while at < header.len() {
        let code = header[at];
        let length = usize::from(
            *header
                .get(at + 1)
                .ok_or_else(|| protocol_error("a parameter without its length"))?,
        );
        let value = header
            .get(at + 2..at + 2 + length)
            .ok_or_else(|| protocol_error("a parameter that runs off the header"))?;
        match code {
            PARAM_SIZE => {
                connect.size_code = value.first().copied().unwrap_or(DEFAULT_SIZE_CODE);
            }
            PARAM_SRC_TSAP => connect.src_tsap = value.to_vec(),
            PARAM_DST_TSAP => connect.dst_tsap = value.to_vec(),
            _ => {}
        }
        at += 2 + length;
    }
    Ok(connect)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect() -> Connect {
        Connect {
            src_ref: 1,
            dst_ref: 0,
            size_code: 10,
            src_tsap: vec![0x01, 0x00],
            dst_tsap: vec![0x01, 0x02],
        }
    }

    #[test]
    fn every_tpdu_round_trips() {
        for tpdu in [
            Tpdu::ConnectRequest(connect()),
            Tpdu::ConnectConfirm(connect()),
            Tpdu::Data {
                last: true,
                payload: b"hello".to_vec(),
            },
            Tpdu::Data {
                last: false,
                payload: Vec::new(),
            },
            Tpdu::Disconnect { reason: 0x80 },
        ] {
            assert_eq!(decode(&encode(&tpdu)).expect("decode"), tpdu);
        }
        let cr = encode(&Tpdu::ConnectRequest(connect()));
        assert_eq!(&cr[..7], &[17, 0xE0, 0, 0, 0, 1, 0]);
        assert_eq!(&cr[7..], &[0xC0, 1, 10, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2]);
        assert_eq!(size_of(10), 1024);
        assert_eq!(size_of(2), 128, "clamped up");
        assert_eq!(size_of(20), 8192, "clamped down");
    }

    #[test]
    fn what_is_not_class_0_is_refused() {
        assert!(decode(&[]).is_err(), "empty");
        assert!(decode(&[9, 0xF0, 0x80]).is_err(), "LI past the end");
        assert!(decode(&[2, 0x70, 0]).is_err(), "AK is class 2");
        assert!(
            decode(&[3, 0xF0, 0, 0]).is_err(),
            "DT with a sequence number"
        );
        assert!(decode(&[6, 0xE0, 0, 0, 0, 1, 0x20]).is_err(), "class 2");
        assert!(
            decode(&[8, 0xE0, 0, 0, 0, 1, 0, 0xC1, 5]).is_err(),
            "runs off"
        );
        assert!(!decode(&[3, 0xE0, 0, 0]).expect_err("short").retryable);
    }
}
