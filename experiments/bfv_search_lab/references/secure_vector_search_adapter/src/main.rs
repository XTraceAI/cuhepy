//! Public-data exact-metric adapter, not a deliverable crypto implementation.
//! Existing author arithmetic/configurations remain unchanged. Signs encode
//! dot(x,q)=d-2*H(x,q) exactly; with Q=2^20 and d<=512 there is no field wrap,
//! quantization error or f32 integer rounding. All m scores are checked.

use std::{collections::BTreeSet, env, fs, time::Instant};
use scorer_core::{Device, Hit, Scorer, Vector};
use scorer_emvp::{EmvpConfig, EmvpScorer};
use scorer_bntm::{BnTmConfig, BnTmScorer};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Query {
    signs: Vec<i8>,
    expected: Vec<u16>,
    source_id: u64,
}

#[derive(Deserialize)]
struct Input {
    dataset: String,
    dimension: usize,
    ids: Vec<u64>,
    rows: Vec<Vec<i8>>,
    queries: Vec<Query>,
    fixture_sha256: String,
}

fn vector(values: &[i8], d: usize) -> Vector {
    assert_eq!(values.len(), d);
    assert!(values.iter().all(|&x| x == -1 || x == 1));
    Vector(values.iter().map(|&x| x as f32).collect())
}

fn finish(hits: Vec<Hit>, input: &Input, score_scale: f32) -> (Vec<u16>, Vec<(u16, u64)>) {
    assert_eq!(hits.len(), input.rows.len());
    let mut scores = vec![None; hits.len()];
    for hit in hits {
        let i = hit.id as usize;
        assert!(i < scores.len() && scores[i].is_none() && hit.score.is_finite());
        let dot = hit.score / score_scale;
        let h = (input.dimension as f32 - dot) / 2.0;
        assert!(h >= 0.0 && h <= input.dimension as f32 && h == h.round(),
                "nonexact score for row {i}: dot={dot} h={h} dimension={}", input.dimension);
        scores[i] = Some(h as u16);
    }
    let scores: Vec<u16> = scores.into_iter().map(Option::unwrap).collect();
    let mut ranked: Vec<_> = scores.iter().copied().zip(input.ids.iter().copied()).collect();
    ranked.sort_unstable();
    ranked.truncate(3);
    (scores, ranked)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("expected public input JSON")?;
    let input: Input = serde_json::from_slice(&fs::read(path)?)?;
    assert!((1..=512).contains(&input.dimension));
    assert!(!input.rows.is_empty() && input.rows.len() <= 32768);
    assert_eq!(input.ids.len(), input.rows.len());
    assert_eq!(input.ids.iter().collect::<BTreeSet<_>>().len(), input.ids.len());
    let vectors: Vec<_> = input.rows.iter().map(|r| vector(r, input.dimension)).collect();
    for query in &input.queries {
        vector(&query.signs, input.dimension);
        let exact: Vec<u16> = input.rows.iter().map(|r| r.iter().zip(&query.signs)
            .filter(|(a, b)| a != b).count() as u16).collect();
        assert_eq!(exact, query.expected);
    }
    let mut cases: Vec<Value> = Vec::new();
    let emvp = EmvpScorer::new();
    let emvp_config = EmvpConfig { key_seed: rand::random(), progress: None,
                                  device: Device::Cpu, vram_budget_bytes: None };
    let t = Instant::now();
    let (handle, build) = emvp.upload_cluster(&emvp_config, &vectors).await?;
    let build_elapsed_us = t.elapsed().as_micros() as u64;
    let cost = emvp.communication_cost(&handle, vectors.len());
    let mut samples = Vec::new();
    for (i, query) in input.queries.iter().enumerate() {
        let q = vector(&query.signs, input.dimension);
        let t = Instant::now();
        let (hits, timing) = emvp.score_with_breakdown(&handle, &q, vectors.len()).await?;
        let a = Instant::now();
        let (scores, top3) = finish(hits, &input, 1.0);
        let adapter_us = a.elapsed().as_micros() as u64;
        let elapsed_us = t.elapsed().as_micros() as u64;
        assert_eq!(scores, query.expected);
        samples.push(json!({"warmup": i == 0, "query_id": query.source_id,
            "encode_us": timing.encode_us, "server_us": timing.server_us,
            "verify_us": 0, "decode_us": timing.decode_us, "adapter_us": adapter_us,
            "elapsed_us": elapsed_us, "all_scores_exact": true, "top3": top3}));
    }
    cases.push(json!({"mode": "emvp_native_hbc", "integrity": "none",
        "setup_elapsed_us": build_elapsed_us, "author_build_us": build.build_duration.as_micros() as u64,
        "cache_hit": build.cache_hit, "query_bytes_model": cost.query_bytes,
        "response_bytes_model": cost.response_bytes, "setup_bytes_model": cost.setup_bytes,
        "samples": samples}));
    drop(handle);
    drop(emvp);
    for verified in [false, true] {
        let scorer = BnTmScorer;
        let config = BnTmConfig { key_seed: rand::random(), verification_enabled: verified,
                                 device: Device::Cpu, ..Default::default() };
        let t = Instant::now();
        let (handle, build) = scorer.upload_cluster(&config, &vectors).await?;
        let build_elapsed_us = t.elapsed().as_micros() as u64;
        let cost = scorer.communication_cost(&handle, vectors.len());
        let mut samples = Vec::new();
        for (i, query) in input.queries.iter().enumerate() {
            let q = vector(&query.signs, input.dimension);
            let t = Instant::now();
            let (hits, timing) = scorer.score_with_breakdown(&handle, &q, vectors.len()).await?;
            let a = Instant::now();
            // Unlike EMVP, the BN scorer API returns the signed QUANTIZED
            // field product, without dividing by Q^2. Binary dots times
            // this power of two remain exactly representable as f32.
            let scale = (config.quantisation_q as f32) * (config.quantisation_q as f32);
            let (scores, top3) = finish(hits, &input, scale);
            let adapter_us = a.elapsed().as_micros() as u64;
            let elapsed_us = t.elapsed().as_micros() as u64;
            assert_eq!(scores, query.expected);
            samples.push(json!({"warmup": i == 0, "query_id": query.source_id,
                "encode_us": timing.encode_us, "server_us": timing.server_us,
                "verify_us": timing.verify_us, "decode_us": timing.decode_us, "adapter_us": adapter_us,
                "elapsed_us": elapsed_us, "all_scores_exact": true, "top3": top3}));
        }
        cases.push(json!({"mode": if verified {"bntm_native_verified"} else {"bntm_native_hbc"},
            "integrity": if verified {"author_protocol2_freivalds"} else {"none"},
            "setup_elapsed_us": build_elapsed_us, "author_build_us": build.build_duration.as_micros() as u64,
            "cache_hit": build.cache_hit, "query_bytes_model": cost.query_bytes,
            "response_bytes_model": cost.response_bytes, "setup_bytes_model": cost.setup_bytes,
            "samples": samples}));
    }
    println!("{}", serde_json::to_string_pretty(&json!({
        "kind": "matched_binary_exact_author_reference", "reference_commit": "519148cf3fddc11277a111774ca8cb92d891e0e3",
        "dataset": input.dataset, "count": vectors.len(), "dimension": input.dimension,
        "fixture_sha256": input.fixture_sha256, "rayon_threads": rayon::current_num_threads(),
        "wire_values_are_author_models": true, "external_security_is_not_certified_by_this_run": true,
        "full_scores_and_stable_id_top3": true, "cases": cases
    }))?);
    Ok(())
}
