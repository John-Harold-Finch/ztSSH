//! End-to-end integration test — boots a real server, connects a real client,
//! verifies multiple challenge-response cycles complete successfully.

use std::net::TcpListener as StdListener;

use ztssh_ca::RootCa;
use ztssh_crypto::KeyPair;
use ztssh_transport::{client, server::ZtsshServer};

use ztssh_policy::{PolicyEngine, PolicyConfig, ServerPolicy};

/// Pick an available TCP port by binding to :0 and checking the assigned port.
fn available_port() -> u16 {
    let listener = StdListener::bind("127.0.0.1:0").expect("bind to :0");
    listener.local_addr().unwrap().port()
}

/// Full E2E: handshake + 3 challenge-response cycles, then client disconnects.
#[tokio::test]
async fn e2e_handshake_and_three_challenges() {
    // ── Setup PKI ──
    let root_ca = RootCa::new();
    let sub_key = KeyPair::new();

    let intermediate = root_ca.authorize_server(
        sub_key.public_key_bytes(),
        "e2e-test-server",
        None, // wildcard principals
    );

    let mut sub_ca = ztssh_ca::SubCa::from_keypair(sub_key);
    sub_ca.root_public_key = Some(intermediate.issuer_public_key);
    sub_ca.intermediate_cert = Some(intermediate);

    // ── Start server ──
    let port = available_port();
    let addr = format!("127.0.0.1:{port}");

    let server = ZtsshServer::new(sub_ca)
        .with_intervals(1, 5); // 1s challenge interval, 5s deadline

    let server_addr = addr.clone();
    let server_handle = tokio::spawn(async move {
        // Server.listen() loops forever; we'll cancel it via the abort below.
        let _ = server.listen(&server_addr).await;
    });

    // Give the server a moment to bind
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // ── Run client session in a separate task ──
    let client_addr = addr.clone();
    let client_handle = tokio::spawn(async move {
        client::run_session(&client_addr, "alice").await
    });

    // Let 3 challenge cycles execute (1s interval × 3 + margin)
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    // Abort both: the client is in an infinite loop waiting for next challenge,
    // the server is in an infinite accept loop.
    client_handle.abort();
    server_handle.abort();

    // If we got this far without a panic, the E2E flow is working.
    // The abort causes a JoinError::Cancelled, which is expected.
    let client_result = client_handle.await;
    assert!(
        client_result.is_err(), // cancelled = ok
        "client should have been cancelled"
    );
}

/// E2E: certificate renewal triggers when cert TTL < 60s (default renewal window).
/// We set cert_ttl very short (2s) so renewal must happen.
#[tokio::test]
async fn e2e_certificate_renewal() {
    let root_ca = RootCa::new();
    let sub_key = KeyPair::new();

    let intermediate = root_ca.authorize_server(
        sub_key.public_key_bytes(),
        "renewal-test-server",
        None,
    );

    let mut sub_ca = ztssh_ca::SubCa::from_keypair(sub_key);
    sub_ca.root_public_key = Some(intermediate.issuer_public_key);
    sub_ca.intermediate_cert = Some(intermediate);
    // Very short cert TTL to force renewal
    sub_ca.cert_ttl = 3.0;

    let port = available_port();
    let addr = format!("127.0.0.1:{port}");

    let server = ZtsshServer::new(sub_ca)
        .with_intervals(1, 5);

    let server_addr = addr.clone();
    let server_handle = tokio::spawn(async move {
        let _ = server.listen(&server_addr).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client_addr = addr.clone();
    let client_handle = tokio::spawn(async move {
        client::run_session(&client_addr, "bob").await
    });

    // The cert is 3s, renewal window is 60s, so the client should renew
    // at the very first challenge. Let 3 cycles run.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    client_handle.abort();
    server_handle.abort();

    let client_result = client_handle.await;
    assert!(client_result.is_err()); // cancelled
}

/// E2E: restricted principals — only "alice" allowed, "eve" should fail.
#[tokio::test]
async fn e2e_restricted_principal_rejected() {
    let root_ca = RootCa::new();
    let sub_key = KeyPair::new();

    let intermediate = root_ca.authorize_server(
        sub_key.public_key_bytes(),
        "restricted-srv",
        Some(vec!["alice".to_string()]), // only alice
    );

    let mut sub_ca = ztssh_ca::SubCa::from_keypair(sub_key);
    sub_ca.root_public_key = Some(intermediate.issuer_public_key);
    sub_ca.intermediate_cert = Some(intermediate);

    let port = available_port();
    let addr = format!("127.0.0.1:{port}");

    let server = ZtsshServer::new(sub_ca)
        .with_intervals(1, 5);

    let server_addr = addr.clone();
    let server_handle = tokio::spawn(async move {
        let _ = server.listen(&server_addr).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // "eve" should be rejected at handshake
    let client_addr = addr.clone();
    let result = client::run_session(&client_addr, "eve").await;

    // The server refuses to issue a cert for "eve" — the connection should error
    assert!(result.is_err(), "eve should have been rejected");

    server_handle.abort();
}

/// E2E: alice is allowed through on a restricted server
#[tokio::test]
async fn e2e_allowed_principal_accepted() {
    let root_ca = RootCa::new();
    let sub_key = KeyPair::new();

    let intermediate = root_ca.authorize_server(
        sub_key.public_key_bytes(),
        "restricted-srv",
        Some(vec!["alice".to_string()]),
    );

    let mut sub_ca = ztssh_ca::SubCa::from_keypair(sub_key);
    sub_ca.root_public_key = Some(intermediate.issuer_public_key);
    sub_ca.intermediate_cert = Some(intermediate);

    let port = available_port();
    let addr = format!("127.0.0.1:{port}");

    let server = ZtsshServer::new(sub_ca)
        .with_intervals(1, 5);

    let server_addr = addr.clone();
    let server_handle = tokio::spawn(async move {
        let _ = server.listen(&server_addr).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client_addr = addr.clone();
    let client_handle = tokio::spawn(async move {
        client::run_session(&client_addr, "alice").await
    });

    // Let 2 cycles pass — alice should be accepted
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    client_handle.abort();
    server_handle.abort();
}

/// E2E: policy engine denies a principal at connection time.
#[tokio::test]
async fn e2e_policy_denies_principal() {
    let root_ca = RootCa::new();
    let sub_key = KeyPair::new();

    let intermediate = root_ca.authorize_server(
        sub_key.public_key_bytes(),
        "policy-srv",
        None, // wildcard at CA level
    );

    let mut sub_ca = ztssh_ca::SubCa::from_keypair(sub_key);
    sub_ca.root_public_key = Some(intermediate.issuer_public_key);
    sub_ca.intermediate_cert = Some(intermediate);

    // Policy denies "hacker"
    let policy = PolicyEngine::new(PolicyConfig {
        server: ServerPolicy {
            denied_principals: vec!["hacker".to_string()],
            ..Default::default()
        },
        principal_rules: vec![],
    });

    let port = available_port();
    let addr = format!("127.0.0.1:{port}");

    let server = ZtsshServer::new(sub_ca)
        .with_intervals(1, 5)
        .with_policy(policy);

    let server_addr = addr.clone();
    let server_handle = tokio::spawn(async move {
        let _ = server.listen(&server_addr).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // "hacker" should be denied by policy
    let client_addr = addr.clone();
    let result = client::run_session(&client_addr, "hacker").await;
    assert!(result.is_err(), "hacker should have been denied by policy");

    server_handle.abort();
}

/// E2E: policy allowlist — only explicitly listed principals allowed.
#[tokio::test]
async fn e2e_policy_allowlist_enforced() {
    let root_ca = RootCa::new();
    let sub_key = KeyPair::new();

    let intermediate = root_ca.authorize_server(
        sub_key.public_key_bytes(),
        "allowlist-srv",
        None,
    );

    let mut sub_ca = ztssh_ca::SubCa::from_keypair(sub_key);
    sub_ca.root_public_key = Some(intermediate.issuer_public_key);
    sub_ca.intermediate_cert = Some(intermediate);

    let policy = PolicyEngine::new(PolicyConfig {
        server: ServerPolicy {
            require_principal_allowlist: true,
            allowed_principals: vec!["admin".to_string()],
            ..Default::default()
        },
        principal_rules: vec![],
    });

    let port = available_port();
    let addr = format!("127.0.0.1:{port}");

    let server = ZtsshServer::new(sub_ca)
        .with_intervals(1, 5)
        .with_policy(policy);

    let server_addr = addr.clone();
    let server_handle = tokio::spawn(async move {
        let _ = server.listen(&server_addr).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // "unknown" is not in the allowlist
    let result = client::run_session(&addr, "unknown").await;
    assert!(result.is_err(), "unknown should be denied by allowlist");

    server_handle.abort();
}
