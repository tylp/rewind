#[derive(Debug, PartialEq)]
/// Enumeration of possible statuses for a replay packet.
pub enum ReplayPacketStatus {
    Sent,
    NotSent,
    Failed,
}
