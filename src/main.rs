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

fn main() {
    // 生成密钥对
    let keypair = SchnorrKeyPair::generate();
    let msg = b"hello schnorr!";
    // 签名
    let (r, s) = schnorr_sign(&keypair.privkey, msg);
    // 验证
    let valid = schnorr_verify(&keypair.pubkey, msg, &r, &s);
    println!("签名是否有效: {}", valid);
}
