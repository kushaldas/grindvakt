#![cfg(feature = "redis")]

use grindvakt::{RedisStore, TokenUseStore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string())
}

fn test_prefix() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after Unix epoch")
        .as_nanos();
    let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "grindvakt:test:{}:{}:",
        std::process::id(),
        now + u128::from(counter)
    )
}

fn cleanup(redis_url: &str, key: &str) {
    let Ok(client) = redis::Client::open(redis_url) else {
        return;
    };
    let Ok(mut conn) = client.get_connection() else {
        return;
    };
    let _ = redis::cmd("DEL").arg(key).query::<()>(&mut conn);
}

#[tokio::test]
#[ignore = "requires a running Redis server; use `just redis-test`"]
async fn redis_store_consumes_token_once_on_server() {
    let redis_url = redis_url();
    let token_hash = "code:server-backed";
    let prefix = test_prefix();
    let key = format!("{prefix}{token_hash}");
    let store = RedisStore::new(&redis_url)
        .expect("REDIS_URL should point at a running Redis server")
        .with_key_prefix(prefix);

    cleanup(&redis_url, &key);

    assert!(store.consume(token_hash, 30).await.unwrap());
    assert!(!store.consume(token_hash, 30).await.unwrap());

    cleanup(&redis_url, &key);
}

#[tokio::test]
#[ignore = "requires a running Redis server; use `just redis-test`"]
async fn redis_store_allows_reuse_after_expiry_on_server() {
    let redis_url = redis_url();
    let token_hash = "refresh:server-backed";
    let prefix = test_prefix();
    let key = format!("{prefix}{token_hash}");
    let store = RedisStore::new(&redis_url)
        .expect("REDIS_URL should point at a running Redis server")
        .with_key_prefix(prefix);

    cleanup(&redis_url, &key);

    assert!(store.consume(token_hash, 1).await.unwrap());
    assert!(!store.consume(token_hash, 1).await.unwrap());
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert!(store.consume(token_hash, 1).await.unwrap());

    cleanup(&redis_url, &key);
}
