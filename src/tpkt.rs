//! TPKT, RFC 1006 section 6: the four-byte frame that carries one TPDU over
//! TCP, because TCP is a byte stream and ISO transport needs packets.
//!
//! `03 00 LL LL` — version 3, a reserved zero, and the length of the whole
//! frame, header included, big-endian. Nothing else; the TPDU follows.

use std::io::{Read, Write};

use transport::error::{Result, classify, protocol_error};

/// The only TPKT version there is.
pub const VERSION: u8 = 3;
/// The frame header: version, reserved, two length bytes.
pub const HEADER_LEN: usize = 4;
/// The most a frame's length field can say.
pub const MAX_FRAME: usize = 65_535;

/// Write `tpdu` as one frame.
///
/// # Errors
/// A TPDU that does not fit a sixteen-bit length, or a peer that went away.
pub fn write_frame(writer: &mut impl Write, tpdu: &[u8]) -> Result<()> {
    let length = u16::try_from(tpdu.len() + HEADER_LEN)
        .map_err(|_| protocol_error("a TPDU over what a TPKT frame carries"))?;
    let mut frame = Vec::with_capacity(usize::from(length));
    frame.extend_from_slice(&[VERSION, 0]);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(tpdu);
    writer
        .write_all(&frame)
        .map_err(|e| classify("writing a TPKT frame", &e))?;
    writer
        .flush()
        .map_err(|e| classify("flushing a TPKT frame", &e))
}

/// Read one frame's TPDU, or `None` when the peer closed between frames.
///
/// # Errors
/// A version that is not 3, a length shorter than the header itself, or a
/// connection that closes mid-frame.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut head = [0u8; HEADER_LEN];
    let first = reader
        .read(&mut head[..1])
        .map_err(|e| classify("reading a TPKT header", &e))?;
    if first == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut head[1..])
        .map_err(|e| classify("reading a TPKT header", &e))?;
    if head[0] != VERSION {
        return Err(protocol_error(format!(
            "a TPKT version {} where only 3 exists",
            head[0]
        )));
    }
    let length = usize::from(u16::from_be_bytes([head[2], head[3]]));
    if length < HEADER_LEN + 1 {
        return Err(protocol_error("a TPKT frame shorter than its own header"));
    }
    let mut tpdu = vec![0u8; length - HEADER_LEN];
    reader
        .read_exact(&mut tpdu)
        .map_err(|e| classify("reading a TPDU", &e))?;
    Ok(Some(tpdu))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_round_trips_with_its_length_in_the_header() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &[0xF0, 0x80, b'h', b'i']).expect("write");
        assert_eq!(wire, [3, 0, 0, 8, 0xF0, 0x80, b'h', b'i']);
        let back = read_frame(&mut wire.as_slice())
            .expect("read")
            .expect("one");
        assert_eq!(back, [0xF0, 0x80, b'h', b'i']);
        assert!(read_frame(&mut &b""[..]).expect("closed").is_none());
    }

    #[test]
    fn what_is_not_tpkt_is_refused() {
        assert!(
            !read_frame(&mut &[2u8, 0, 0, 5, 0][..])
                .expect_err("v2")
                .retryable
        );
        assert!(read_frame(&mut &[3u8, 0, 0, 4][..]).is_err(), "no TPDU");
        assert!(read_frame(&mut &[3u8, 0, 0, 9, 1][..]).is_err(), "short");
        let mut sink = Vec::new();
        assert!(write_frame(&mut sink, &vec![0u8; MAX_FRAME]).is_err());
    }
}
