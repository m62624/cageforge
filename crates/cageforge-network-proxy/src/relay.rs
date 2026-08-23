// SPDX-License-Identifier: Apache-2.0

//! Bounded bidirectional byte relay.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::sleep;

use crate::GatewayError;

const BUFFER_BYTES: usize = 16 * 1024;

pub(crate) async fn copy_bidirectional<A, B>(
    left: A,
    right: B,
    idle_timeout: Duration,
    byte_limit: Option<NonZeroU64>,
) -> Result<(), GatewayError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (left_read, left_write) = tokio::io::split(left);
    let (right_read, right_write) = tokio::io::split(right);
    let activity = Arc::new(AtomicU64::new(1));
    let idle_activity = Arc::clone(&activity);
    let transferred = Arc::new(AtomicU64::new(0));
    let transfers = async {
        tokio::try_join!(
            copy_direction(
                left_read,
                right_write,
                Arc::clone(&activity),
                Arc::clone(&transferred),
                byte_limit,
            ),
            copy_direction(
                right_read,
                left_write,
                Arc::clone(&activity),
                Arc::clone(&transferred),
                byte_limit,
            )
        )?;
        Ok(())
    };
    tokio::select! {
        result = transfers => result,
        () = wait_until_idle(idle_activity, idle_timeout) => Err(GatewayError::RelayTimedOut),
    }
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    activity: Arc<AtomicU64>,
    transferred: Arc<AtomicU64>,
    byte_limit: Option<NonZeroU64>,
) -> Result<(), GatewayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0; BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        add_transferred(&transferred, read as u64, byte_limit)?;
        writer.write_all(&buffer[..read]).await?;
        activity.fetch_add(1, Ordering::Relaxed);
    }
}

fn add_transferred(
    transferred: &AtomicU64,
    amount: u64,
    limit: Option<NonZeroU64>,
) -> Result<(), GatewayError> {
    let Some(limit) = limit else {
        transferred.fetch_add(amount, Ordering::Relaxed);
        return Ok(());
    };
    let mut current = transferred.load(Ordering::Relaxed);
    loop {
        let Some(updated) = current.checked_add(amount) else {
            return Err(GatewayError::RelayByteLimitExceeded { limit: limit.get() });
        };
        if updated > limit.get() {
            return Err(GatewayError::RelayByteLimitExceeded { limit: limit.get() });
        }
        match transferred.compare_exchange_weak(
            current,
            updated,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(actual) => current = actual,
        }
    }
}

async fn wait_until_idle(activity: Arc<AtomicU64>, timeout: Duration) {
    let mut observed = activity.load(Ordering::Relaxed);
    loop {
        sleep(timeout).await;
        let current = activity.load(Ordering::Relaxed);
        if current == observed {
            return;
        }
        observed = current;
    }
}
