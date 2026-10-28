use super::NativeResult;
use std::{future::Future, time::Duration};

// Revocation is best effort after the private session has been deleted. Keep
// offline sign-out bounded and distinguish local success from remote success.
pub(super) async fn revoke(remote: impl Future<Output = NativeResult<()>>) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(5), remote).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_backend::NativeError;

    #[tokio::test(start_paused = true)]
    async fn revocation_is_bounded_when_the_api_is_blocked() {
        let before = tokio::time::Instant::now();
        assert!(!revoke(std::future::pending()).await);
        assert_eq!(before.elapsed(), Duration::from_secs(5));
        assert!(!revoke(async { Err(NativeError::new("api_unreachable", "offline")) }).await);
        assert!(revoke(async { Ok(()) }).await);
    }
}
