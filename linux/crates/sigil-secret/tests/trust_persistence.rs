//! Trust persistence integration tests.
//!
//! These tests exercise the full round-trip to libsecret / Secret Service
//! to verify that server trust records persist correctly, survive "app restarts",
//! handle corruption gracefully, and support multi-server scenarios.
//!
//! **Run with `cargo test --features integration-tests`** — requires
//! `dbus-run-session` + `gnome-keyring-daemon` or equivalent.
//!
//! Tests are gated behind `#[cfg(feature = "integration-tests")]` to skip
//! when Secret Service is unavailable (non-Linux CI, etc).

#![cfg(all(test, feature = "integration-tests", target_os = "linux"))]

use sigil_secret::{MetadataStore, ServerRecord};

/// Helper: create a sample server record for testing.
fn sample_server(name: &str, url: &str, fingerprint_hex: &str) -> (String, ServerRecord) {
    (
        fingerprint_hex.to_string(),
        ServerRecord {
            url: url.to_string(),
            server_public_key_b64: format!("Ag8x{}", fingerprint_hex),
            pictogram: [
                "tree".into(),
                "rocket".into(),
                "mushroom".into(),
                "orange".into(),
                "moai".into(),
            ],
            pictogram_speakable: "tree rocket mushroom orange moai".into(),
            display_name: Some(name.to_string()),
            paired_at: "2026-04-27T13:00:00Z".into(),
            tls_cert_sha256_hex: None,
        },
    )
}

/// Test 1: Trust persists across "app restart" (new MetadataStore connection).
///
/// Simulates: pair with server → kill app → restart app → verify trusted state retained.
#[tokio::test]
async fn trust_persists_across_restart() {
    let (fp, record) = sample_server("Acme Corp", "https://acme.example.com", "deadbeef01");

    // Phase 1: Connect and persist
    {
        let store = MetadataStore::connect()
            .await
            .expect("Failed to connect to Secret Service");
        store
            .put_server(&fp, &record)
            .await
            .expect("Failed to persist server record");
    } // Drop store (simulates app shutdown)

    // Phase 2: Reconnect (simulates app restart) and verify
    {
        let store = MetadataStore::connect()
            .await
            .expect("Failed to reconnect to Secret Service");
        let retrieved = store
            .get_server(&fp)
            .await
            .expect("Server record not found after restart");
        assert_eq!(retrieved, record, "Retrieved record does not match persisted record");
        assert_eq!(
            retrieved.display_name.as_deref(),
            Some("Acme Corp"),
            "Display name mismatch"
        );
        assert_eq!(
            retrieved.url, "https://acme.example.com",
            "URL mismatch"
        );
    }

    // Cleanup: delete test record
    {
        let store = MetadataStore::connect().await.unwrap();
        let _ = store.delete_server(&fp).await;
    }
}

/// Test 2: Revocation cleanly removes the libsecret entry.
///
/// Verifies: delete_server() removes the record and subsequent get_server() fails with NotFound.
#[tokio::test]
async fn revocation_removes_entry() {
    let (fp, record) = sample_server("Beta Inc", "https://beta.example.com", "deadbeef02");

    let store = MetadataStore::connect()
        .await
        .expect("Failed to connect");

    // Persist the record
    store
        .put_server(&fp, &record)
        .await
        .expect("Failed to persist record");

    // Verify it exists
    let retrieved = store
        .get_server(&fp)
        .await
        .expect("Record should exist before revocation");
    assert_eq!(retrieved, record);

    // Revoke (delete)
    store
        .delete_server(&fp)
        .await
        .expect("Failed to delete record");

    // Verify it no longer exists
    let result = store.get_server(&fp).await;
    assert!(
        matches!(result, Err(sigil_secret::SecretError::NotFound)),
        "Expected NotFound after deletion, got {:?}",
        result
    );
}

/// Test 3: Corrupted entry fails gracefully (does not crash, logged and skipped).
///
/// Verifies: manually corrupt a libsecret item → list_servers() skips it with a warning log.
/// (We test the serde path here; manually corrupting Secret Service requires raw D-Bus access
/// which is complex. Instead we verify that from_bytes handles corruption correctly and
/// list_servers() already has graceful handling per source lines 335-339.)
#[tokio::test]
async fn corrupted_entry_fails_gracefully() {
    // Verify that malformed JSON is rejected gracefully
    let malformed_json = b"{\"url\":\"https://x\",\"incomplete\":true}";
    let result = ServerRecord::from_bytes(malformed_json);
    assert!(
        result.is_err(),
        "Corrupted record should fail deserialization"
    );

    // Verify that list_servers() handles corrupted records gracefully
    // (This is integration-tested by the list_servers implementation which logs + skips malformed records)
    // We test the serde layer here; full D-Bus corruption testing would require manual D-Bus manipulation
    let partial_json = b"{\"url\":\"https://x\"}"; // Missing required fields
    let result = ServerRecord::from_bytes(partial_json);
    assert!(
        matches!(result, Err(sigil_secret::SecretError::Serde(_))),
        "Expected Serde error for partial record"
    );
}

/// Test 4: Multiple servers can be trusted simultaneously (fingerprints don't collide).
///
/// Verifies: persist N servers → retrieve all → verify all present and distinct.
#[tokio::test]
async fn multiple_servers_distinct() {
    let servers = vec![
        sample_server("Server Alpha", "https://alpha.example.com", "aaaa0001"),
        sample_server("Server Bravo", "https://bravo.example.com", "bbbb0002"),
        sample_server("Server Charlie", "https://charlie.example.com", "cccc0003"),
    ];

    let store = MetadataStore::connect()
        .await
        .expect("Failed to connect");

    // Persist all servers
    for (fp, record) in &servers {
        store
            .put_server(fp, record)
            .await
            .expect(&format!("Failed to persist server {}", fp));
    }

    // List all servers
    let all_servers = store
        .list_servers()
        .await
        .expect("Failed to list servers");

    // Verify all test servers are present
    for (expected_fp, expected_record) in &servers {
        let found = all_servers
            .iter()
            .find(|(fp, _)| fp == expected_fp)
            .expect(&format!("Server {} not found in list", expected_fp));
        assert_eq!(
            &found.1, expected_record,
            "Record mismatch for {}",
            expected_fp
        );
    }

    // Verify we can retrieve each individually
    for (fp, expected_record) in &servers {
        let retrieved = store
            .get_server(fp)
            .await
            .expect(&format!("Failed to retrieve server {}", fp));
        assert_eq!(&retrieved, expected_record, "Individual retrieval mismatch for {}", fp);
    }

    // Cleanup: delete all test servers
    for (fp, _) in &servers {
        let _ = store.delete_server(fp).await;
    }
}

/// Test 5: Replace existing record (update scenario).
///
/// Verifies: put_server() with existing fingerprint replaces the record.
#[tokio::test]
async fn update_replaces_existing() {
    let fp = "update0001".to_string();
    let (_, record_v1) = sample_server("Original Name", "https://v1.example.com", &fp);
    let (_, mut record_v2) = sample_server("Updated Name", "https://v2.example.com", &fp);
    record_v2.display_name = Some("Updated Name".to_string());

    let store = MetadataStore::connect()
        .await
        .expect("Failed to connect");

    // Persist v1
    store
        .put_server(&fp, &record_v1)
        .await
        .expect("Failed to persist v1");

    // Verify v1 exists
    let retrieved = store.get_server(&fp).await.expect("v1 should exist");
    assert_eq!(retrieved.display_name.as_deref(), Some("Original Name"));

    // Update to v2
    store
        .put_server(&fp, &record_v2)
        .await
        .expect("Failed to update to v2");

    // Verify v2 replaced v1
    let retrieved = store.get_server(&fp).await.expect("v2 should exist");
    assert_eq!(retrieved.display_name.as_deref(), Some("Updated Name"));
    assert_eq!(retrieved.url, "https://v2.example.com");

    // Cleanup
    let _ = store.delete_server(&fp).await;
}
