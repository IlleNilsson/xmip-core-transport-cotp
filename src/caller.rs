//! A caller's connection, kept open at a Receive Location between its
//! messages.
//!
//! The connections are kept beside the listener
//! (`transport::serving::Serving`): the CR is a connection's first turn,
//! answered with CC, and every message after it — its DT TPDUs up to the
//! one with EOT — is one turn of its own, handed up as a Stream; a DR or a
//! close ends the connection. Each turn is bounded whole by the node's
//! `[tuning] receive_turn`, so a caller that stops partway is turned away
//! and the next is served (ADR-0018, amendment 2026-11-14). Until then a
//! receive accepted one caller and read its messages until it disconnected,
//! on the Location's own thread, every other caller waiting behind it.

use std::net::{SocketAddr, TcpStream};

use transport::deadline::Within;
use transport::error::Result;
use transport::serving::{Open, Turn};
use transport::{Acknowledgement, Arrived};

use crate::AT_MOST_ONCE;
use crate::connection::Connection;

/// One caller's connection, confirmed on its first turn.
pub struct Caller {
    connection: Connection,
    confirmed: bool,
}

impl Caller {
    /// A caller's new connection, from `peer`, at most 2^`size_code` a
    /// TPDU, its CR not yet read.
    ///
    /// # Errors
    /// Where the connection could not be cloned for its writes.
    pub fn new(stream: Within, peer: SocketAddr, size_code: u8) -> Result<Self> {
        Ok(Self {
            connection: Connection::accepted(stream, peer, size_code)?,
            confirmed: false,
        })
    }

    /// One turn: the CR answered, where the connection has not had it, or
    /// the next message, whole. A caller that disconnected or closed has
    /// gone. Acceptance is at-most-once ([`AT_MOST_ONCE`]).
    ///
    /// # Errors
    /// Where the caller did not open with CR, broke off mid-message, or
    /// sent a TPDU that is not data.
    pub fn turn(&mut self) -> Result<Turn<Arrived>> {
        if !self.confirmed {
            self.confirmed = self.connection.confirm()?;
            return Ok(if self.confirmed {
                Turn::Nothing
            } else {
                Turn::Closed
            });
        }
        let Some(message) = self.connection.next_data()? else {
            return Ok(Turn::Closed);
        };
        let arrived = Arrived::whole(
            self.connection.origin(),
            message,
            Acknowledgement::at_most_once(AT_MOST_ONCE),
        )
        .from_peer(self.connection.peer());
        Ok(Turn::Taken(arrived))
    }
}

impl Open for Caller {
    fn socket(&self) -> &TcpStream {
        self.connection.socket()
    }

    /// A TPDU the last read took beside its own waits in the buffer.
    fn waiting(&self) -> bool {
        self.connection.buffered()
    }
}
