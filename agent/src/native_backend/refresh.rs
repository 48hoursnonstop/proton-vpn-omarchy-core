use super::*;

const ACCOUNT_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);
const FAILED_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

impl NativeRuntime {
    // Callers hold auth_write so refreshed tokens cannot race login/logout.
    async fn get_refreshing_session(
        &self,
        endpoint: &str,
        session: &mut SessionData,
    ) -> NativeResult<Value> {
        let mut auth = session_bootstrap::stored_api_session(session);
        match self.api.get(endpoint, &auth).await {
            Err(error) if error.code == "authentication_expired" => {
                self.api.refresh(&mut auth).await?;
                session.access_token = auth.access_token.clone();
                session.refresh_token = auth.refresh_token.clone();
                session.scopes = auth.scopes.clone();
                self.persist_session_data(session.clone()).await?;
                self.api.get(endpoint, &auth).await
            }
            result => result,
        }
    }

    pub(super) async fn ensure_client_config(&self) -> NativeResult<()> {
        let _auth = self.auth_write.lock().await;
        let (mut session, _) = self.require_session().await?;
        let now = unix_seconds()? as f64;
        let cached = self.state.read().await.client_config.clone();
        if cached
            .as_ref()
            .is_some_and(|config| client_config_fresh(config, now))
        {
            return Ok(());
        }
        let fetched = self
            .get_refreshing_session("/vpn/v2/clientconfig", &mut session)
            .await
            .and_then(session_bootstrap::client_config);
        match fetched {
            Ok((config, value)) => self.save_client_config(config, value).await,
            Err(_) if cached.is_some() => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn save_client_config(&self, config: ClientConfig, value: Value) -> NativeResult<()> {
        let path = self.paths.client_config.clone();
        tokio::task::spawn_blocking(move || settings_store::save_value(&path, &value))
            .await
            .map_err(join_error)??;
        self.state.write().await.client_config = Some(config);
        Ok(())
    }

    pub(super) async fn refresh_remote_data(&self, force: bool) -> NativeResult<Value> {
        let _auth = if force {
            self.auth_write.lock().await
        } else {
            let Ok(guard) = self.auth_write.try_lock() else {
                return Ok(json!({"skipped": true}));
            };
            guard
        };
        let (mut session, _) = self.require_session().await?;
        let now = Instant::now();
        let refresh_account = force
            || self
                .state
                .read()
                .await
                .remote_refresh_after
                .map_or(true, |after| now >= after);
        let mut account_updated = false;
        let mut config_updated = false;
        let mut location_updated = false;
        let mut first_error = None;
        if refresh_account {
            // Set a bounded retry even if transport fails; a blocked network
            // must not cause an API request on every observation tick.
            self.state.write().await.remote_refresh_after = Some(now + FAILED_REFRESH_INTERVAL);
            let account = self
                .get_refreshing_session("/vpn/v2", &mut session)
                .await
                .and_then(session_bootstrap::account_info);
            match account {
                Ok(info) => {
                    session.vpn.vpninfo = info;
                    self.persist_session_data(session.clone()).await?;
                    account_updated = true;
                    self.state.write().await.remote_refresh_after =
                        Some(now + ACCOUNT_REFRESH_INTERVAL);
                }
                Err(error) => first_error = Some(error),
            }
            match self
                .get_refreshing_session("/vpn/v2/clientconfig", &mut session)
                .await
                .and_then(session_bootstrap::client_config)
            {
                Ok((config, value)) => {
                    self.save_client_config(config, value).await?;
                    config_updated = true;
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        let network = self.network.clone();
        let physical = tokio::task::spawn_blocking(move || {
            let identity = network.physical_network_identity()?;
            let can_probe = network.observe()?.state == TunnelState::Disconnected
                && network.conflicting_interfaces()?.is_empty();
            Ok::<_, NativeError>((identity, can_probe))
        })
        .await
        .map_err(join_error)??;
        let (identity, can_probe) = physical;
        if !identity.is_empty() {
            let should_refresh = {
                let mut state = self.state.write().await;
                if state.location_identity.as_ref() != Some(&identity) {
                    state.physical_location_known = false;
                }
                can_probe
                    && (force
                        || ((!state.physical_location_known
                            || state.location_identity.as_ref() != Some(&identity)
                            || refresh_account)
                            && state
                                .location_retry_after
                                .map_or(true, |after| now >= after)))
            };
            if should_refresh {
                self.state.write().await.location_retry_after = Some(now + FAILED_REFRESH_INTERVAL);
                let fetched = self
                    .get_refreshing_session("/vpn/v1/location", &mut session)
                    .await
                    .and_then(session_bootstrap::location);
                match fetched {
                    Ok(location) => {
                        // Never relabel a VPN exit address as the physical IP
                        // if a connection started while the HTTP request ran.
                        let network = self.network.clone();
                        let expected_identity = identity.clone();
                        let unchanged = tokio::task::spawn_blocking(move || {
                            Ok::<_, NativeError>(
                                network.observe()?.state == TunnelState::Disconnected
                                    && network.conflicting_interfaces()?.is_empty()
                                    && network.physical_network_identity()? == expected_identity,
                            )
                        })
                        .await
                        .map_err(join_error)??;
                        if unchanged {
                            session.vpn.location = location;
                            self.persist_session_data(session).await?;
                            let mut state = self.state.write().await;
                            state.location_identity = Some(identity);
                            state.physical_location_known = true;
                            location_updated = true;
                        }
                    }
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }
        }
        self.emit_account().await;
        self.emit_features().await;
        self.emit_device_location().await;
        if (force && !account_updated) || (!account_updated && !config_updated && !location_updated)
        {
            if let Some(error) = first_error {
                return Err(error);
            }
        }
        Ok(
            json!({"account_updated": account_updated, "client_config_updated": config_updated, "location_updated": location_updated}),
        )
    }
}

fn client_config_fresh(config: &ClientConfig, now: f64) -> bool {
    config
        .extra
        .get("ExpirationTime")
        .and_then(Value::as_f64)
        .is_some_and(|expires| expires.is_finite() && expires > now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_and_legacy_client_configs_require_refresh() {
        let value =
            json!({"DefaultPorts": {"WireGuard": {"UDP": [51820], "TCP": [443], "TLS": [443]}}});
        let legacy: ClientConfig = serde_json::from_value(value.clone()).unwrap();
        assert!(!client_config_fresh(&legacy, 100.0));
        let (fresh, _) = session_bootstrap::client_config(value).unwrap();
        assert!(client_config_fresh(&fresh, unix_seconds().unwrap() as f64));
        assert!(!client_config_fresh(&fresh, f64::MAX));
    }

    #[test]
    fn malformed_remote_account_and_location_do_not_replace_cached_values() {
        assert!(session_bootstrap::account_info(json!({"VPN": {"MaxTier": "2"}})).is_err());
        assert!(session_bootstrap::account_info(json!({"VPN": {"MaxTier": 256}})).is_err());
        assert!(session_bootstrap::location(json!({"IP": "not-an-ip", "Country": "MX"})).is_err());
        assert!(session_bootstrap::location(json!({"IP": "203.0.113.2", "Country": "MX"})).is_ok());
    }
}
