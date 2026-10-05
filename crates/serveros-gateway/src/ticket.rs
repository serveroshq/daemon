use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TicketError {
    #[error("the ticket is malformed")]
    Malformed,
    #[error("the ticket has expired")]
    Expired,
    #[error("the ticket signature does not match")]
    Signature,
}

pub fn verify(
    secret: &str,
    machine: &str,
    session: &str,
    ticket: &str,
    now: i64,
) -> Result<(), TicketError> {
    let (expires_str, mac_hex) = ticket.split_once('.').ok_or(TicketError::Malformed)?;
    let expires: i64 = expires_str.parse().map_err(|_| TicketError::Malformed)?;
    let presented = hex::decode(mac_hex).map_err(|_| TicketError::Malformed)?;

    if presented.len() != 32 {
        return Err(TicketError::Malformed);
    }

    let expected = hmac_sha256(
        secret.as_bytes(),
        format!("{machine}|{session}|{expires}").as_bytes(),
    );

    if !constant_time_eq(&expected, &presented) {
        return Err(TicketError::Signature);
    }

    if expires < now {
        return Err(TicketError::Expired);
    }

    Ok(())
}

pub fn sign(secret: &str, machine: &str, session: &str, expires: i64) -> String {
    let mac = hmac_sha256(
        secret.as_bytes(),
        format!("{machine}|{session}|{expires}").as_bytes(),
    );

    format!("{expires}.{}", hex::encode(mac))
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];

    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let inner_pad: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
    let outer_pad: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();

    let inner = Sha256::new()
        .chain_update(&inner_pad)
        .chain_update(message)
        .finalize();
    let outer = Sha256::new()
        .chain_update(&outer_pad)
        .chain_update(inner)
        .finalize();

    outer.into()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231_case_two() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");

        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn tickets_round_trip_and_bind_to_machine_and_session() {
        let ticket = sign("s3cret-s3cret-s3cret", "m-1", "sess", 1_000);

        assert_eq!(
            verify("s3cret-s3cret-s3cret", "m-1", "sess", &ticket, 999),
            Ok(())
        );
        assert_eq!(
            verify("s3cret-s3cret-s3cret", "m-2", "sess", &ticket, 999),
            Err(TicketError::Signature)
        );
        assert_eq!(
            verify("s3cret-s3cret-s3cret", "m-1", "other", &ticket, 999),
            Err(TicketError::Signature)
        );
        assert_eq!(
            verify("s3cret-s3cret-s3cret", "m-1", "sess", &ticket, 1_001),
            Err(TicketError::Expired)
        );
        assert_eq!(
            verify("s3cret-s3cret-s3cret", "m-1", "sess", "nope", 0),
            Err(TicketError::Malformed)
        );
    }

    #[test]
    fn matches_the_panel_side_php_signature() {
        let ticket = sign("secret", "abc", "def", 1_700_000_000);

        assert_eq!(
            ticket,
            format!(
                "1700000000.{}",
                hex::encode(hmac_sha256(b"secret", b"abc|def|1700000000"))
            )
        );
    }
}
