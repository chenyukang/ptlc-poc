use k256::elliptic_curve::ff::Field; // for Scalar::random
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256}; // for Scalar::from_repr

// Schnorr签名结构体
struct SchnorrKeyPair {
    privkey: Scalar,
    pubkey: ProjectivePoint,
}

impl SchnorrKeyPair {
    fn generate() -> Self {
        let mut rng = OsRng;
        let privkey = Scalar::random(&mut rng);
        let pubkey = ProjectivePoint::GENERATOR * privkey;
        SchnorrKeyPair { privkey, pubkey }
    }
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
    let hash = Sha256::digest(data);
    Scalar::from_repr(hash.into()).unwrap()
}

fn schnorr_sign(privkey: &Scalar, msg: &[u8]) -> (ProjectivePoint, Scalar) {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let r_point = ProjectivePoint::GENERATOR * k;
    let r_bytes = r_point.to_encoded_point(false);
    let mut hasher = Sha256::new();
    hasher.update(r_bytes.as_bytes());
    hasher.update(msg);
    let e = hash_to_scalar(&hasher.finalize());
    let s = k + e * (*privkey);
    (r_point, s)
}

fn schnorr_verify(pubkey: &ProjectivePoint, msg: &[u8], r: &ProjectivePoint, s: &Scalar) -> bool {
    let r_bytes = r.to_encoded_point(false);
    let mut hasher = Sha256::new();
    hasher.update(r_bytes.as_bytes());
    hasher.update(msg);
    let e = hash_to_scalar(&hasher.finalize());
    let s_g = ProjectivePoint::GENERATOR * (*s);
    let r_plus_e_y = *r + (*pubkey * e);
    s_g == r_plus_e_y
}

// ========== 适配器签名结构与流程 ==========
// 适配器签名 (Adaptor Signature) 结构
struct AdaptorSignature {
    r: ProjectivePoint, // Schnorr 签名的 R 点
    s_hat: Scalar,      // 适配器签名 s_hat = k + e * offset
}

// 生成适配器签名（只知道 offset，无法生成完整签名）
fn schnorr_adaptor_sign(offset: &Scalar, msg: &[u8]) -> (AdaptorSignature, Scalar) {
    let mut rng = OsRng;
    let k = Scalar::random(&mut rng);
    let r = ProjectivePoint::GENERATOR * k;
    let r_bytes = r.to_encoded_point(false);
    let mut hasher = Sha256::new();
    hasher.update(r_bytes.as_bytes());
    hasher.update(msg);
    let e = hash_to_scalar(&hasher.finalize());
    let s_hat = k + e * (*offset); // 适配器签名
    (AdaptorSignature { r, s_hat }, k)
}

// 完整签名恢复：s = s_hat + e * secret
fn schnorr_adaptor_complete(adaptor_sig: &AdaptorSignature, secret: &Scalar, msg: &[u8]) -> Scalar {
    let r_bytes = adaptor_sig.r.to_encoded_point(false);
    let mut hasher = Sha256::new();
    hasher.update(r_bytes.as_bytes());
    hasher.update(msg);
    let e = hash_to_scalar(&hasher.finalize());
    adaptor_sig.s_hat + e * (*secret)
}

// 校验适配器签名（只校验 offset 公钥）
fn schnorr_adaptor_verify(
    offset_pub: &ProjectivePoint,
    msg: &[u8],
    adaptor_sig: &AdaptorSignature,
) -> bool {
    let r_bytes = adaptor_sig.r.to_encoded_point(false);
    let mut hasher = Sha256::new();
    hasher.update(r_bytes.as_bytes());
    hasher.update(msg);
    let e = hash_to_scalar(&hasher.finalize());
    let s_g = ProjectivePoint::GENERATOR * adaptor_sig.s_hat;
    let r_plus_e_y = adaptor_sig.r + (*offset_pub * e);
    s_g == r_plus_e_y
}

// 计算 Schnorr 签名 challenge e
fn schnorr_challenge(r: &ProjectivePoint, msg: &[u8]) -> Scalar {
    let r_bytes = r.to_encoded_point(false);
    let mut hasher = Sha256::new();
    hasher.update(r_bytes.as_bytes());
    hasher.update(msg);
    hash_to_scalar(&hasher.finalize())
}

// 通过下游签名和适配器签名恢复 preimage
fn recover_preimage(s_full: &Scalar, adaptor_sig: &AdaptorSignature, msg: &[u8]) -> Scalar {
    let e = schnorr_challenge(&adaptor_sig.r, msg);
    (*s_full - adaptor_sig.s_hat) * e.invert().unwrap()
}

// 打印每一跳的 claim/payment 过程
fn claim_and_recover(
    who: &str,
    s_full: &Scalar,
    adaptor_sig: &AdaptorSignature,
    expected_secret: &Scalar,
    msg: &[u8],
) -> Scalar {
    println!("{} 向上游 claim payment，泄露 s = {:?}", who, s_full);
    let recovered = recover_preimage(s_full, adaptor_sig, msg);
    println!("{} 通过 s 恢复 D 的 secret: {:?}", who, recovered);
    assert_eq!(recovered, *expected_secret);
    recovered
}

fn ptlc_demo() {
    // 1. D 生成私钥 s，公钥 S = s*G
    let mut rng = OsRng;
    let s = Scalar::random(&mut rng);
    let s_pub = ProjectivePoint::GENERATOR * s;
    println!("D's secret s: {:?}", s);
    println!("D's public S: {:?}", s_pub);

    // 2. A 生成随机 a, b, c
    let a = Scalar::random(&mut rng);
    let b = Scalar::random(&mut rng);
    let c = Scalar::random(&mut rng);
    let abc = a + b + c;
    println!("A's a: {:?}", a);
    println!("B's b: {:?}", b);
    println!("C's c: {:?}", c);
    println!("D's offset (a+b+c): {:?}", abc);

    // 3. 构造每个 hop 的 offset 公钥
    let ab_offset = a; // A->B
    let bc_offset = a + b; // B->C
    let cd_offset = a + b + c; // C->D
    let ab_pub = ProjectivePoint::GENERATOR * (ab_offset + s);
    let bc_pub = ProjectivePoint::GENERATOR * (bc_offset + s);
    let cd_pub = ProjectivePoint::GENERATOR * (cd_offset + s);
    println!("A->B 适配器签名公钥: (a+s)*G = {:?}", ab_pub);
    println!("B->C 适配器签名公钥: (a+b+s)*G = {:?}", bc_pub);
    println!("C->D 适配器签名公钥: (a+b+c+s)*G = {:?}", cd_pub);

    // 4. A 为每个 hop 构造适配器签名
    let msg = b"ptlc payment";
    let (adaptor_sig_cd, _k_cd) = schnorr_adaptor_sign(&cd_offset, msg); // C->D
    let (adaptor_sig_bc, _k_bc) = schnorr_adaptor_sign(&bc_offset, msg); // B->C
    let (adaptor_sig_ab, _k_ab) = schnorr_adaptor_sign(&ab_offset, msg); // A->B

    // 5. D 拥有 s，完成 C->D 的签名
    let s_cd = schnorr_adaptor_complete(&adaptor_sig_cd, &s, msg);
    let valid_cd = schnorr_verify(&cd_pub, msg, &adaptor_sig_cd.r, &s_cd);
    println!("D 完整签名 s_cd 是否有效: {}", valid_cd);

    // 6. D 向 C claim payment，泄露 s_cd
    println!("\nD 向 C claim payment，泄露 s_cd = {:?}", s_cd);
    let recovered_s_c = claim_and_recover("C", &s_cd, &adaptor_sig_cd, &s, msg);
    // C 校验 B->C 的适配器签名
    let valid_bc = schnorr_adaptor_verify(&bc_pub, msg, &adaptor_sig_bc);
    println!("C 校验 B->C 适配器签名: {}", valid_bc);
    // C 用 recovered_s_c 完成 B->C 的签名
    let s_bc = schnorr_adaptor_complete(&adaptor_sig_bc, &recovered_s_c, msg);
    let valid_bc_full = schnorr_verify(&bc_pub, msg, &adaptor_sig_bc.r, &s_bc);
    println!("C 完整签名 s_bc 是否有效: {}", valid_bc_full);

    // 7. C 向 B claim payment，泄露 s_bc
    let recovered_s_b = claim_and_recover("B", &s_bc, &adaptor_sig_bc, &s, msg);
    let valid_ab = schnorr_adaptor_verify(&ab_pub, msg, &adaptor_sig_ab);
    println!("B 校验 A->B 适配器签名: {}", valid_ab);
    let s_ab = schnorr_adaptor_complete(&adaptor_sig_ab, &recovered_s_b, msg);
    let valid_ab_full = schnorr_verify(&ab_pub, msg, &adaptor_sig_ab.r, &s_ab);
    println!("B 完整签名 s_ab 是否有效: {}", valid_ab_full);

    // 8. B 向 A claim payment，泄露 s_ab
    let recovered_s_a = claim_and_recover("A", &s_ab, &adaptor_sig_ab, &s, msg);
    assert_eq!(recovered_s_a, s);
}

fn main() {
    println!("--- Schnorr 签名 Demo ---");
    // 生成密钥对
    let keypair = SchnorrKeyPair::generate();
    let msg = b"hello schnorr!";
    // 签名
    let (r, s) = schnorr_sign(&keypair.privkey, msg);
    // 验证
    let valid = schnorr_verify(&keypair.pubkey, msg, &r, &s);
    println!("签名是否有效: {}", valid);

    println!("\n--- PTLC Demo ---");
    ptlc_demo();
}
