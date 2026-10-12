use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::Error as ClientError;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

#[derive(Clone)]
pub struct UpstreamClient {
    client: Client<HttpConnector, Full<Bytes>>,
}

impl UpstreamClient {
    pub fn new(connect_timeout: Duration) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(connect_timeout));
        connector.enforce_http(true);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Self { client }
    }

    pub async fn request(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>, ClientError> {
        self.client.request(request).await
    }
}
