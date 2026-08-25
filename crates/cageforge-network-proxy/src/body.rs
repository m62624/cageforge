// SPDX-License-Identifier: Apache-2.0

//! Streaming HTTP body bounds shared by requests and responses.

use std::error::Error;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Body, Frame, SizeHint};
use tokio::time::{Instant, Sleep};

use crate::GatewayError;

pub(crate) type BoxError = Box<dyn Error + Send + Sync>;
pub(crate) type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

pub(crate) struct TransferBudget {
    transferred: AtomicU64,
    limit: Option<NonZeroU64>,
}

struct GuardedBody<B> {
    inner: Pin<Box<B>>,
    idle: Pin<Box<Sleep>>,
    idle_timeout: Duration,
    budget: Arc<TransferBudget>,
}

impl TransferBudget {
    pub(crate) fn new(limit: Option<NonZeroU64>) -> Arc<Self> {
        Arc::new(Self {
            transferred: AtomicU64::new(0),
            limit,
        })
    }

    fn add(&self, amount: u64) -> Result<(), GatewayError> {
        let Some(limit) = self.limit else {
            return Ok(());
        };
        let mut current = self.transferred.load(Ordering::Relaxed);
        loop {
            let Some(updated) = current.checked_add(amount) else {
                return Err(GatewayError::RelayByteLimitExceeded { limit: limit.get() });
            };
            if updated > limit.get() {
                return Err(GatewayError::RelayByteLimitExceeded { limit: limit.get() });
            }
            match self.transferred.compare_exchange_weak(
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
}

impl<B> GuardedBody<B> {
    fn new(inner: B, idle_timeout: Duration, budget: Arc<TransferBudget>) -> Self {
        Self {
            inner: Box::pin(inner),
            idle: Box::pin(tokio::time::sleep(idle_timeout)),
            idle_timeout,
            budget,
        }
    }
}

impl<B> Body for GuardedBody<B>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                let amount = frame
                    .data_ref()
                    .map_or(0, |data| u64::try_from(data.len()).unwrap_or(u64::MAX));
                if let Err(error) = self.budget.add(amount) {
                    return Poll::Ready(Some(Err(Box::new(error))));
                }
                let deadline = Instant::now() + self.idle_timeout;
                self.idle.as_mut().reset(deadline);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(Box::new(error)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => match self.idle.as_mut().poll(context) {
                Poll::Ready(()) => Poll::Ready(Some(Err(Box::new(GatewayError::RelayTimedOut)))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pub(crate) fn guarded<B>(body: B, idle_timeout: Duration, budget: Arc<TransferBudget>) -> ProxyBody
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Error + Send + Sync + 'static,
{
    GuardedBody::new(body, idle_timeout, budget).boxed_unsync()
}

pub(crate) fn empty() -> ProxyBody {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub(crate) fn text(message: &'static str) -> ProxyBody {
    http_body_util::Full::new(Bytes::from_static(message.as_bytes()))
        .map_err(|never| match never {})
        .boxed_unsync()
}

#[cfg(test)]
#[path = "body_tests.rs"]
mod tests;
