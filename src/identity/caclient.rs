// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::BTreeMap;

use crate::config::RootCert;
use async_trait::*;
use dyn_clone::DynClone;
use prost_types::value::Kind;
use prost_types::Struct;
use tonic::codegen::InterceptedService;
use tracing::{instrument, warn};

use crate::identity::auth::AuthSource;
use crate::identity::manager::Identity;
use crate::identity::Error;
use crate::tls::{self, SanChecker, TlsGrpcChannel};
use crate::xds::istio::ca::istio_certificate_service_client::IstioCertificateServiceClient;
use crate::xds::istio::ca::IstioCertificateRequest;

#[derive(Clone)]
pub struct CaClient {
    pub client: IstioCertificateServiceClient<InterceptedService<TlsGrpcChannel, AuthSource>>,
    pub opts: Options,
}

#[derive(Clone)]
pub struct Options {
    pub trust_domain: String,
}

#[async_trait]
pub trait CertificateProvider: DynClone + Send + Sync + 'static {
    async fn fetch_certificate(&self, id: &Identity) -> Result<tls::Certs, Error>;
}

dyn_clone::clone_trait_object!(CertificateProvider);

impl CaClient {
    pub fn new(
        address: String,
        trust_domain: String,
        root_cert: RootCert,
        auth: AuthSource,
    ) -> Result<CaClient, Error> {
        let svc = tls::grpc_connector(address, root_cert)?;
        let client = IstioCertificateServiceClient::with_interceptor(svc, auth);
        Ok(CaClient {
            client,
            opts: Options { trust_domain },
        })
    }
}

#[async_trait]
impl CertificateProvider for CaClient {
    #[instrument(skip_all)]
    async fn fetch_certificate(&self, id: &Identity) -> Result<tls::Certs, Error> {
        let new_id: Identity = match id {
            Identity::Spiffe {
                trust_domain: _,
                namespace,
                service_account,
            } => Identity::Spiffe {
                trust_domain: self.opts.trust_domain.to_owned(),
                namespace: namespace.to_owned(),
                service_account: service_account.to_owned(),
            },
        };
        let cs = tls::CsrOptions {
            san: new_id.to_string(),
        }
        .generate()?;
        let csr: Vec<u8> = cs.csr;
        let pkey = cs.pkey;

        let csr = std::str::from_utf8(&csr).map_err(Error::Utf8)?.to_string();
        let req = IstioCertificateRequest {
            csr,
            validity_duration: 60 * 60 * 24, // 24 hours
            metadata: Some(Struct {
                fields: BTreeMap::from([(
                    "ImpersonatedIdentity".into(),
                    prost_types::Value {
                        kind: Some(Kind::StringValue(new_id.to_string())),
                    },
                )]),
            }),
        };
        let resp = self
            .client
            .clone()
            .create_certificate(req)
            .await?
            .into_inner();
        let leaf = resp
            .cert_chain
            .first()
            .ok_or_else(|| Error::EmptyResponse(new_id.to_owned()))?
            .as_bytes();
        let chain = if resp.cert_chain.len() > 1 {
            resp.cert_chain[1..].iter().map(|s| s.as_bytes()).collect()
        } else {
            warn!("no chain certs for: {}", new_id);
            vec![]
        };
        let certs = tls::cert_from(&pkey, leaf, chain);
        certs
            .verify_san(&new_id)
            .map_err(|_| Error::SanError(new_id.to_owned()))?;
        Ok(certs)
    }
}

pub mod mock {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::sync::RwLock;
    use tokio::time::Instant;

    use crate::identity::{CertificateProvider, Identity};
    use crate::tls::{generate_test_certs_at, Certs};

    use super::*;

    #[derive(Default)]
    struct ClientState {
        fetches: Vec<Identity>,
    }

    #[derive(Clone)]
    pub struct ClientConfig {
        pub cert_lifetime: Duration,
        pub time_conv: crate::time::Converter,
        // If non-zero, causes fetch_certificate calls to sleep for the specified duration before
        // returning. This is helpful to let tests that pause tokio time get more control over code
        // execution.
        pub fetch_latency: Duration,
    }

    impl Default for ClientConfig {
        fn default() -> Self {
            Self {
                fetch_latency: Duration::ZERO,
                cert_lifetime: Duration::from_secs(10),
                time_conv: crate::time::Converter::new(),
            }
        }
    }

    #[derive(Clone)]
    pub struct CaClient {
        cfg: ClientConfig,
        state: Arc<RwLock<ClientState>>,
    }

    impl CaClient {
        pub fn new(cfg: ClientConfig) -> CaClient {
            CaClient {
                cfg,
                state: Default::default(),
            }
        }

        pub fn cert_lifetime(&self) -> Duration {
            self.cfg.cert_lifetime
        }

        // Returns a list of fetch_certificate calls, in the order they happened. Calls are added
        // just before the function returns (ie. after the potential sleep controlled by the
        // fetch_latency config option).
        pub async fn fetches(&self) -> Vec<Identity> {
            self.state.read().await.fetches.clone()
        }

        pub async fn clear_fetches(&self) {
            self.state.write().await.fetches.clear();
        }
    }

    #[async_trait]
    impl CertificateProvider for CaClient {
        async fn fetch_certificate(&self, id: &Identity) -> Result<Certs, Error> {
            if self.cfg.fetch_latency != Duration::ZERO {
                tokio::time::sleep(self.cfg.fetch_latency).await;
            }

            // Get SystemTime::now() via Instant::now() to allow mocking in tests.
            let not_before = self
                .cfg
                .time_conv
                .instant_to_system_time(Instant::now().into())
                .expect("SystemTime cannot represent current time. Was the process started in extreme future?");
            let not_after = not_before + self.cfg.cert_lifetime;

            let certs = generate_test_certs_at(&id.to_owned().into(), not_before, not_after);

            self.state.write().await.fetches.push(id.to_owned());
            return Ok(certs);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use matches::assert_matches;

    use crate::{
        identity::{Error, Identity},
        test_helpers, tls,
        xds::istio::ca::IstioCertificateResponse,
    };

    use super::CertificateProvider;

    async fn test_ca_client_with_response(
        res: IstioCertificateResponse,
        trust_domain: String,
    ) -> Result<tls::Certs, Error> {
        let (mock, mut ca_client) = test_helpers::ca::CaServer::spawn().await;
        ca_client.opts.trust_domain = trust_domain.to_string();
        mock.send(Ok(res)).unwrap();
        ca_client.fetch_certificate(&Identity::default()).await
    }

    #[tokio::test]
    async fn empty_chain() {
        let res = test_ca_client_with_response(
            IstioCertificateResponse { cert_chain: vec![] },
            "".to_string(),
        )
        .await;
        assert_matches!(res, Err(Error::EmptyResponse(_)));
    }

    #[tokio::test]
    async fn wrong_identity() {
        let id = Identity::Spiffe {
            service_account: "wrong-sa".to_string(),
            namespace: "foo".to_string(),
            trust_domain: "cluster.local".to_string(),
        };
        let certs =
            tls::generate_test_certs(&id.into(), Duration::from_secs(0), Duration::from_secs(0));

        let res = test_ca_client_with_response(
            IstioCertificateResponse {
                cert_chain: vec![String::from_utf8(certs.x509().to_pem().unwrap()).unwrap()],
            },
            "cluster.local".to_string(),
        )
        .await;
        assert_matches!(res, Err(Error::SanError(_)));
    }

    #[tokio::test]
    async fn fetch_certificate() {
        let new_id: Identity = match &Identity::default() {
            Identity::Spiffe {
                trust_domain: _,
                namespace,
                service_account,
            } => Identity::Spiffe {
                trust_domain: "test.trust.domain".to_string(),
                namespace: namespace.to_owned(),
                service_account: service_account.to_owned(),
            },
        };
        let certs = tls::generate_test_certs(
            &new_id.into(),
            Duration::from_secs(0),
            Duration::from_secs(0),
        );
        let res = test_ca_client_with_response(
            IstioCertificateResponse {
                cert_chain: vec![String::from_utf8(certs.x509().to_pem().unwrap()).unwrap()],
            },
            "test.trust.domain".to_string(),
        )
        .await;
        assert_matches!(res, Ok(_));
    }
}
