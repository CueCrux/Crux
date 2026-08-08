// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.
// TurboQuant low-bit quantizer for the `.ccxe` dense lane.
//
// Ported (algorithm only) from Google Research's TurboQuant via the MIT-licensed
// `turbovec` crate (https://github.com/RyanCodrai/turbovec) — we do NOT vendor the
// crate or its ANN index, only the quantizer technique, per ExecPlan
// `corecrux-turboquant-ccxe-quant-mode` (T.5 supply-chain).
//
// Pipeline (per vector, encode): L2-normalize -> seeded structured rotation
// (Rademacher sign-flip + Fast Walsh-Hadamard Transform, a few rounds, padded to
// the next power of two) -> per-coordinate scalar quantization against pooled
// Lloyd-Max reconstruction levels -> bit-pack to `bits` per coordinate.
//
// Why this recovers recall-per-bit: the orthonormal rotation Gaussianizes the
// coordinate distribution so a single shared Lloyd-Max level set is near-optimal
// for every coordinate, and — being orthonormal — it preserves inner products, so
// scoring rotates the QUERY into the same space and dots against the decoded doc
// (length-renormalized). FWHT padding adds zeros, which contribute nothing to the
// inner product, so cosine in rotated space equals cosine in the original space up
// to quantization noise.

/// Per-segment TurboQuant parameters. Reproduces the rotation + dequant levels at
/// read time without storing any per-vector or per-segment dense matrix — only a
/// seed, the padded width, the bit width, and `2^bits` reconstruction levels.
#[derive(Debug, Clone, PartialEq)]
pub struct TurboParams {
    pub seed: u64,
    pub orig_dim: usize,
    pub padded_dim: usize,
    pub bits: u8,
    /// Sorted reconstruction levels; len == 2^bits.
    pub levels: Vec<f32>,
}

/// Number of (sign-flip + FWHT) mixing rounds. 3 rounds gives good Gaussianisation
/// of the coordinate marginals while staying cheap and exactly reproducible.
const ROUNDS: usize = 3;

#[inline]
pub fn next_pow2(n: usize) -> usize {
    let mut p = 1;
    while p < n {
        p <<= 1;
    }
    p.max(1)
}

/// Deterministic splitmix64 — dependency-free seeded RNG (no supply-chain surface).
#[inline]
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Rademacher ±1 signs for one round, derived from (seed, round).
fn round_signs(seed: u64, round: usize, n: usize) -> Vec<f32> {
    let mut st = seed ^ ((round as u64).wrapping_mul(0xD1B54A32D192ED03));
    (0..n)
        .map(|_| if splitmix64(&mut st) & 1 == 0 { 1.0f32 } else { -1.0f32 })
        .collect()
}

/// In-place orthonormal Fast Walsh-Hadamard Transform. `buf.len()` must be a power
/// of two. Normalised by 1/sqrt(n) so the transform is orthonormal (norm-preserving).
fn fwht_orthonormal(buf: &mut [f32]) {
    let n = buf.len();
    debug_assert!(n.is_power_of_two());
    let mut len = 1;
    while len < n {
        let mut i = 0;
        while i < n {
            for j in i..i + len {
                let a = buf[j];
                let b = buf[j + len];
                buf[j] = a + b;
                buf[j + len] = a - b;
            }
            i += len << 1;
        }
        len <<= 1;
    }
    let scale = 1.0f32 / (n as f32).sqrt();
    for v in buf.iter_mut() {
        *v *= scale;
    }
}

/// Apply the seeded structured rotation in place (sign-flip + FWHT, ROUNDS times).
/// Orthonormal and exactly reproducible from `seed`. `buf.len()` must be padded_dim
/// (a power of two).
fn apply_rotation(buf: &mut [f32], seed: u64) {
    let n = buf.len();
    for r in 0..ROUNDS {
        let signs = round_signs(seed, r, n);
        for (v, s) in buf.iter_mut().zip(signs.iter()) {
            *v *= *s;
        }
        fwht_orthonormal(buf);
    }
}

/// Pad `vec` to `padded_dim` with zeros and apply the rotation. Returns the rotated
/// padded vector. Does NOT normalise (caller decides).
pub fn rotate_padded(vec: &[f32], params: &TurboParams) -> Vec<f32> {
    let mut buf = vec![0.0f32; params.padded_dim];
    buf[..vec.len().min(params.padded_dim)].copy_from_slice(&vec[..vec.len().min(params.padded_dim)]);
    apply_rotation(&mut buf, params.seed);
    buf
}

/// Invert the rotation: recover the original-space vector (length `orig_dim`) from a
/// rotated padded vector. The rotation is orthonormal (sign-flip + FWHT are each
/// self-inverse), so the inverse is the forward rounds in reverse with FWHT applied
/// before the sign-flip. Used by the external decode accessors so consumers
/// (compaction re-encode, navtree clustering) see original — not rotated — space.
pub fn inverse_rotate_to_orig(rotated_padded: &[f32], params: &TurboParams) -> Vec<f32> {
    let n = params.padded_dim;
    let mut buf = rotated_padded.to_vec();
    buf.resize(n, 0.0);
    for r in (0..ROUNDS).rev() {
        fwht_orthonormal(&mut buf); // self-inverse (orthonormal)
        let signs = round_signs(params.seed, r, n);
        for (v, s) in buf.iter_mut().zip(signs.iter()) {
            *v *= *s;
        }
    }
    buf.truncate(params.orig_dim);
    buf
}

#[inline]
fn l2_normalise(v: &mut [f32]) {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-12 {
        let inv = 1.0 / norm;
        for x in v.iter_mut() {
            *x *= inv;
        }
    }
}

/// Quantise one coordinate to the nearest reconstruction level; returns the level
/// index (the code). `levels` is sorted ascending.
#[inline]
fn nearest_code(x: f32, levels: &[f32]) -> u8 {
    // Binary search the decision boundaries (midpoints between adjacent levels).
    let mut lo = 0usize;
    let mut hi = levels.len() - 1;
    while lo < hi {
        let mid = usize::midpoint(lo, hi);
        let boundary = 0.5 * (levels[mid] + levels[mid + 1]);
        if x <= boundary {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo as u8
}

/// Train pooled Lloyd-Max reconstruction levels (`2^bits` of them) on a sample of
/// rotated coordinates. Deterministic given the input. Levels returned sorted.
pub fn train_levels(rotated_coords: &[f32], bits: u8) -> Vec<f32> {
    let k = 1usize << bits;
    if rotated_coords.is_empty() {
        // Degenerate: symmetric uniform levels in [-1, 1].
        return (0..k).map(|i| -1.0 + 2.0 * (i as f32 + 0.5) / k as f32).collect();
    }
    let mut sorted: Vec<f32> = rotated_coords.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    // Init levels at evenly spaced quantiles (good Lloyd-Max starting point).
    let mut levels: Vec<f32> = (0..k)
        .map(|i| {
            let q = (i as f32 + 0.5) / k as f32;
            sorted[((q * sorted.len() as f32) as usize).min(sorted.len() - 1)]
        })
        .collect();
    dedupe_jitter(&mut levels);
    // Lloyd iterations: assign -> recompute centroid.
    for _ in 0..25 {
        let mut sums = vec![0.0f64; k];
        let mut counts = vec![0u64; k];
        for &x in &sorted {
            let c = nearest_code(x, &levels) as usize;
            sums[c] += x as f64;
            counts[c] += 1;
        }
        let mut changed = false;
        for c in 0..k {
            if counts[c] > 0 {
                let m = (sums[c] / counts[c] as f64) as f32;
                if (m - levels[c]).abs() > 1e-7 {
                    changed = true;
                }
                levels[c] = m;
            }
        }
        levels.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        dedupe_jitter(&mut levels);
        if !changed {
            break;
        }
    }
    levels
}

/// Ensure strictly increasing levels (binary-search boundaries require it).
fn dedupe_jitter(levels: &mut [f32]) {
    for i in 1..levels.len() {
        if levels[i] <= levels[i - 1] {
            levels[i] = levels[i - 1] + 1e-6;
        }
    }
}

/// Bytes needed to bit-pack `padded_dim` codes at `bits` each (byte-aligned per
/// vector for O(1) random access).
#[inline]
pub fn packed_vector_len(padded_dim: usize, bits: u8) -> usize {
    (padded_dim * bits as usize).div_ceil(8)
}

/// Encode one f32 vector to packed codes (normalise -> rotate -> standardise per
/// coordinate -> quantise -> pack).
pub fn encode_vector(vec: &[f32], params: &TurboParams) -> Vec<u8> {
    let mut buf = vec![0.0f32; params.padded_dim];
    let n = vec.len().min(params.padded_dim);
    buf[..n].copy_from_slice(&vec[..n]);
    l2_normalise(&mut buf);
    apply_rotation(&mut buf, params.seed);
    let mut out = vec![0u8; packed_vector_len(params.padded_dim, params.bits)];
    for (i, &x) in buf.iter().enumerate() {
        let code = nearest_code(x, &params.levels);
        write_code(&mut out, i, params.bits, code);
    }
    out
}

/// Decode one packed vector back to its f32 rotated-space representation (level value
/// re-scaled by the per-coordinate scale).
pub fn decode_vector(packed: &[u8], params: &TurboParams) -> Vec<f32> {
    (0..params.padded_dim)
        .map(|i| params.levels[read_code(packed, i, params.bits) as usize])
        .collect()
}

#[inline]
fn write_code(buf: &mut [u8], idx: usize, bits: u8, code: u8) {
    let bit = idx * bits as usize;
    let byte = bit / 8;
    let shift = bit % 8;
    let mask = ((1u16 << bits) - 1) as u8;
    buf[byte] |= (code & mask) << shift;
    // bits ∈ {2,4} and we are byte-aligned per code (8 % bits == 0), so a code
    // never straddles a byte boundary — no carry into byte+1 needed.
}

#[inline]
fn read_code(buf: &[u8], idx: usize, bits: u8) -> u8 {
    let bit = idx * bits as usize;
    let byte = bit / 8;
    let shift = bit % 8;
    let mask = ((1u16 << bits) - 1) as u8;
    (buf[byte] >> shift) & mask
}

/// Cosine of a (decoded, rotated) doc vector against an already-rotated query.
/// Length-renormalised by the decoded vector's actual norm (Protocol: corrects
/// quantisation energy loss).
#[inline]
pub fn cosine_rotated(decoded: &[f32], rotated_query: &[f32], query_norm: f32) -> f32 {
    let mut dot = 0.0f32;
    let mut dnorm = 0.0f32;
    for (d, q) in decoded.iter().zip(rotated_query.iter()) {
        dot += d * q;
        dnorm += d * d;
    }
    let dnorm = dnorm.sqrt().max(1e-10);
    dot / (dnorm * query_norm.max(1e-10))
}

/// Build segment params + collect a coordinate sample, then train levels. Returns
/// the params ready for `encode_vector`. `seed` is caller-chosen (store it).
pub fn fit(vectors: &[Vec<f32>], orig_dim: usize, bits: u8, seed: u64) -> TurboParams {
    let padded_dim = next_pow2(orig_dim);
    // Sample rotated coordinates across up to 4096 vectors for level training.
    let mut sample = Vec::new();
    let stride = (vectors.len() / 4096).max(1);
    for v in vectors.iter().step_by(stride) {
        let mut buf = vec![0.0f32; padded_dim];
        let n = v.len().min(padded_dim);
        buf[..n].copy_from_slice(&v[..n]);
        l2_normalise(&mut buf);
        apply_rotation(&mut buf, seed);
        sample.extend_from_slice(&buf);
    }
    let levels = train_levels(&sample, bits);
    TurboParams {
        seed,
        orig_dim,
        padded_dim,
        bits,
        levels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_vec(seed: &mut u64, dim: usize) -> Vec<f32> {
        (0..dim)
            .map(|_| (splitmix64(seed) as f64 / u64::MAX as f64 * 2.0 - 1.0) as f32)
            .collect()
    }

    #[test]
    fn fwht_is_orthonormal() {
        let mut v = vec![1.0, 2.0, -3.0, 0.5];
        let n0 = v.iter().map(|x| x * x).sum::<f32>();
        fwht_orthonormal(&mut v);
        let n1 = v.iter().map(|x| x * x).sum::<f32>();
        assert!((n0 - n1).abs() < 1e-4, "FWHT must preserve norm: {n0} vs {n1}");
    }

    #[test]
    fn inverse_rotation_recovers_original() {
        let p = TurboParams {
            seed: 1234,
            orig_dim: 6,
            padded_dim: 8,
            bits: 4,
            levels: vec![],
        };
        let mut s = 3u64;
        let x = rand_vec(&mut s, 6);
        let rotated = rotate_padded(&x, &p);
        let back = inverse_rotate_to_orig(&rotated, &p);
        assert_eq!(back.len(), 6);
        for (a, b) in x.iter().zip(back.iter()) {
            assert!((a - b).abs() < 1e-3, "inverse must recover original: {a} vs {b}");
        }
    }

    #[test]
    fn rotation_preserves_inner_product() {
        let p = TurboParams {
            seed: 42,
            orig_dim: 6,
            padded_dim: 8,
            bits: 4,
            levels: vec![],
        };
        let mut s = 7u64;
        let a = rand_vec(&mut s, 6);
        let b = rand_vec(&mut s, 6);
        let dot0: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
        let ra = rotate_padded(&a, &p);
        let rb = rotate_padded(&b, &p);
        let dot1: f32 = ra.iter().zip(&rb).map(|(x, y)| x * y).sum();
        assert!(
            (dot0 - dot1).abs() < 1e-3,
            "rotation must preserve <a,b>: {dot0} vs {dot1}"
        );
    }

    #[test]
    fn roundtrip_parity_within_bound() {
        // 4-bit should reconstruct a unit vector with small max-diff in rotated space.
        let mut s = 11u64;
        let vecs: Vec<Vec<f32>> = (0..512).map(|_| rand_vec(&mut s, 64)).collect();
        let params = fit(&vecs, 64, 4, 123);
        let mut max_diff = 0.0f32;
        for v in vecs.iter().take(32) {
            // reference: normalised + rotated (no quant)
            let mut ref_buf = v.clone();
            ref_buf.resize(params.padded_dim, 0.0);
            l2_normalise(&mut ref_buf);
            apply_rotation(&mut ref_buf, params.seed);
            let dec = decode_vector(&encode_vector(v, &params), &params);
            for (a, b) in ref_buf.iter().zip(dec.iter()) {
                max_diff = max_diff.max((a - b).abs());
            }
        }
        assert!(max_diff < 0.15, "4-bit max-diff too large: {max_diff}");
    }

    #[test]
    fn cosine_recall_neutral_topk() {
        // Quantised cosine must rank the true nearest neighbour first on a clean set.
        let mut s = 99u64;
        let n = 400;
        let vecs: Vec<Vec<f32>> = (0..n).map(|_| rand_vec(&mut s, 128)).collect();
        let params = fit(&vecs, 128, 4, 555);
        let packed: Vec<Vec<u8>> = vecs.iter().map(|v| encode_vector(v, &params)).collect();

        let mut agree = 0;
        for query in vecs.iter().take(40) {
            // exact nearest (cosine) over raw f32
            let qn = query.iter().map(|x| x * x).sum::<f32>().sqrt();
            let exact = (0..n)
                .max_by(|&i, &j| {
                    let ci = cos(query, &vecs[i], qn);
                    let cj = cos(query, &vecs[j], qn);
                    ci.partial_cmp(&cj).unwrap()
                })
                .unwrap();
            // quantised nearest
            let rq = rotate_padded(query, &params);
            let rqn = rq.iter().map(|x| x * x).sum::<f32>().sqrt();
            let approx = (0..n)
                .max_by(|&i, &j| {
                    let ci = cosine_rotated(&decode_vector(&packed[i], &params), &rq, rqn);
                    let cj = cosine_rotated(&decode_vector(&packed[j], &params), &rq, rqn);
                    ci.partial_cmp(&cj).unwrap()
                })
                .unwrap();
            if exact == approx {
                agree += 1;
            }
        }
        assert!(agree >= 38, "top-1 agreement too low: {agree}/40");
    }

    fn cos(a: &[f32], b: &[f32], an: f32) -> f32 {
        let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
        let bn = b.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-10);
        dot / (an.max(1e-10) * bn)
    }

    #[test]
    fn two_bit_packs_and_unpacks() {
        let params = TurboParams {
            seed: 1,
            orig_dim: 8,
            padded_dim: 8,
            bits: 2,
            levels: vec![-1.5, -0.5, 0.5, 1.5],
        };
        let v = vec![1.0, -1.0, 0.2, -0.2, 0.9, -0.9, 0.0, 0.5];
        let packed = encode_vector(&v, &params);
        assert_eq!(packed.len(), packed_vector_len(8, 2)); // 8*2/8 = 2 bytes
        let dec = decode_vector(&packed, &params);
        assert_eq!(dec.len(), 8);
        for x in dec {
            assert!(params.levels.contains(&x));
        }
    }
}
