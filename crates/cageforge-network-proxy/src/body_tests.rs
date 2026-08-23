// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use pretty_assertions::assert_eq;

use super::{TransferBudget, guarded};

#[tokio::test]
async fn guarded_body_preserves_frames_below_or_without_a_limit() {
    for limit in [None, NonZeroU64::new(4)] {
        let mut body = guarded(
            Full::<Bytes>::from("data"),
            Duration::from_secs(1),
            TransferBudget::new(limit),
        );
        let frame = body.frame().await.unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"data"));
        assert!(body.frame().await.is_none());
    }
}

#[tokio::test]
async fn guarded_body_shares_one_bidirectional_byte_budget() {
    let budget = TransferBudget::new(NonZeroU64::new(5));
    let mut first = guarded(
        Full::<Bytes>::from("abc"),
        Duration::from_secs(1),
        Arc::clone(&budget),
    );
    let mut second = guarded(Full::<Bytes>::from("def"), Duration::from_secs(1), budget);
    first.frame().await.unwrap().unwrap();
    let error = second.frame().await.unwrap().unwrap_err();
    assert!(error.to_string().contains("5-byte limit"));
}

#[derive(Debug)]
struct PendingBody;

impl hyper::body::Body for PendingBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn guarded_body_times_out_while_a_frame_is_stalled() {
    let mut body = guarded(
        PendingBody,
        Duration::from_secs(1),
        TransferBudget::new(None),
    );
    let frame = tokio::spawn(async move { body.frame().await });
    tokio::time::advance(Duration::from_secs(1)).await;
    let error = frame.await.unwrap().unwrap().unwrap_err();
    assert!(error.to_string().contains("inactivity"));
}
