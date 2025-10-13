//! (De)Serialization with serde

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{
    de::{DeserializeOwned, Error as DeError, SeqAccess, Unexpected, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

use core::fmt;
use std::{borrow::Cow, marker::PhantomData};

use crate::group::Group;

/// Serialize raw bytes as base64url for human-readable formats, or raw bytes
/// for binary formats.
pub fn serialize_bytes<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(value))
    } else {
        serializer.serialize_bytes(value)
    }
}

/// Deserialize raw bytes; returns a `Cow<[u8]>` to avoid copies when the format
/// can lend us bytes (binary formats), and allocates only when necessary
/// (JSON/base64).
pub fn deserialize_bytes_cow<'de, D>(deserializer: D) -> Result<Cow<'de, [u8]>, D::Error>
where
    D: Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        // Accept borrowed or owned strings.
        let s: Cow<'de, str> = <Cow<'de, str> as Deserialize>::deserialize(deserializer)?;
        Base64UrlUnpadded::decode_vec(&s)
            .map(Cow::Owned)
            .map_err(|_| D::Error::invalid_value(Unexpected::Str(&s), &"base64url-encoded data"))
    } else {
        // Binary formats can often provide borrowed bytes.
        <Cow<'de, [u8]>>::deserialize(deserializer)
    }
}

/// Backward-compatible shim that materializes a `Vec<u8>`.
pub fn deserialize_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match deserialize_bytes_cow(deserializer)? {
        Cow::Borrowed(b) => b.to_vec(),
        Cow::Owned(v) => v,
    })
}

/// Common functionality for serialization helpers.
pub trait Helper: Serialize + DeserializeOwned {
    const PLURAL_DESCRIPTION: &'static str;
    type Target;

    fn from_target(target: &Self::Target) -> Self;
    fn into_target(self) -> Self::Target;
}

/// Helper type to (de)serialize public scalars.
///
/// Secret scalars should be wrapped in a secret/zeroizing type instead.
#[derive(Debug)]
pub struct ScalarHelper<G: Group>(G::Scalar);

impl<G: Group> ScalarHelper<G> {
    #[inline]
    pub fn serialize<S>(scalar: &G::Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![0u8; G::SCALAR_SIZE];
        G::scalar_to_bytes(&mut bytes, scalar);
        serialize_bytes(&bytes, serializer)
    }

    #[inline]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<G::Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_bytes_cow(deserializer)?;
        if bytes.len() != G::SCALAR_SIZE {
            let expected_len = G::SCALAR_SIZE.to_string();
            return Err(D::Error::invalid_length(
                bytes.len(),
                &expected_len.as_str(),
            ));
        }
        G::scalar_from_bytes(&bytes)
            .ok_or_else(|| D::Error::custom("bytes do not represent a group scalar"))
    }
}

impl<G: Group> Serialize for ScalarHelper<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(&self.0, serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for ScalarHelper<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::deserialize(deserializer).map(Self)
    }
}

impl<G: Group> Helper for ScalarHelper<G> {
    const PLURAL_DESCRIPTION: &'static str = "group scalars";
    type Target = G::Scalar;

    fn from_target(target: &Self::Target) -> Self {
        // Assumes Copy; if your scalars are not Copy, switch to `target.clone()`.
        Self(*target)
    }

    fn into_target(self) -> Self::Target {
        self.0
    }
}

/// Helper type to (de)serialize group points.
#[derive(Debug)]
pub struct PointHelper<G: Group>(G::Point);

impl<G: Group> PointHelper<G> {
    #[inline]
    pub fn serialize<S>(point: &G::Point, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = vec![0u8; G::POINT_SIZE];
        G::point_to_bytes(&mut bytes, point);
        serialize_bytes(&bytes, serializer)
    }

    #[inline]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<G::Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_bytes_cow(deserializer)?;
        if bytes.len() != G::POINT_SIZE {
            let expected_len = G::POINT_SIZE.to_string();
            return Err(D::Error::invalid_length(
                bytes.len(),
                &expected_len.as_str(),
            ));
        }
        G::point_from_bytes(&bytes)
            .ok_or_else(|| D::Error::custom("bytes do not represent a group point"))
    }
}

impl<G: Group> Serialize for PointHelper<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(&self.0, serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for PointHelper<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::deserialize(deserializer).map(Self)
    }
}

impl<G: Group> Helper for PointHelper<G> {
    const PLURAL_DESCRIPTION: &'static str = "group points";
    type Target = G::Point;

    fn from_target(target: &Self::Target) -> Self {
        // Assumes Copy; if your points are not Copy, switch to `target.clone()`.
        Self(*target)
    }

    fn into_target(self) -> Self::Target {
        self.0
    }
}

/// Serialize/deserialize a vector of `T::Target` with a compile-time minimum
/// length.
pub struct VecHelper<T, const MIN: usize>(PhantomData<T>);

impl<T: Helper, const MIN: usize> VecHelper<T, MIN> {
    #[inline]
    fn new() -> Self {
        Self(PhantomData)
    }

    pub fn serialize<S>(values: &[T::Target], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        debug_assert!(values.len() >= MIN);
        serializer.collect_seq(values.iter().map(T::from_target))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<T::Target>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(Self::new())
    }
}

impl<'de, T: Helper, const MIN: usize> Visitor<'de> for VecHelper<T, MIN> {
    type Value = Vec<T::Target>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at least {MIN} {}", T::PLURAL_DESCRIPTION)
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = if let Some(hint) = access.size_hint() {
            if hint < MIN {
                return Err(A::Error::invalid_length(hint, &self));
            }
            Vec::with_capacity(hint)
        } else {
            Vec::new()
        };

        while let Some(helper) = access.next_element::<T>()? {
            out.push(helper.into_target());
        }

        if out.len() >= MIN {
            Ok(out)
        } else {
            Err(A::Error::invalid_length(out.len(), &self))
        }
    }
}

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "p256")]
    pub type G = crate::p256::P256Group;

    #[cfg(feature = "k256")]
    pub type G = crate::k256::K256Group;

    #[cfg(feature = "ristretto")]
    pub type G = crate::ristretto::RistrettoGroup;

    #[cfg(feature = "p384")]
    pub type G = crate::p384::P384Group;

    pub use crate::group::{Group, GroupPoint, GroupScalar};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(bound = "")]
    struct TestObject<G: Group> {
        #[serde(with = "ScalarHelper::<G>")]
        scalar: G::Scalar,
        #[serde(with = "PointHelper::<G>")]
        point: G::Point,
        #[serde(with = "VecHelper::<ScalarHelper<G>, 2>")]
        more_scalars: Vec<G::Scalar>,
    }

    impl<G: Group> TestObject<G> {
        fn sample() -> Self {
            let mut rng = rand::thread_rng();
            Self {
                scalar: 12345_u64.into(),
                point: G::generator() * &G::scalar_random(&mut rng),
                more_scalars: vec![7_u64.into(), 890_u64.into()],
            }
        }
    }

    #[test]
    fn helpers_roundtrip_borrowed_and_owned() {
        let object: TestObject<G> = TestObject::sample();

        // Borrowing path (from_value can often lend &str/&[u8])
        let json_val = serde_json::to_value(&object).unwrap();
        let copy1: TestObject<G> = serde_json::from_value(json_val).unwrap();
        assert_eq!(copy1, object);

        // Owned path (from_str materializes fresh owned strings)
        let json_str = serde_json::to_string(&object).unwrap();
        let copy2: TestObject<G> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(copy2, object);
    }

    #[test]
    fn scalar_helper_invalid_scalar() {
        let object: TestObject<G> = TestObject::sample();
        let mut json = serde_json::to_value(object).unwrap();

        // too short: "test" -> 4 bytes
        json.as_object_mut()
            .unwrap()
            .insert("scalar".into(), "dGVzdA".into());

        let err = serde_json::from_value::<TestObject<G>>(json.clone()).unwrap_err();
        let err_string = err.to_string();
        // The exact expected length depends on the backend.
        assert!(
            err_string.contains("invalid length 4")
                && err_string.contains(&format!("expected {}", G::SCALAR_SIZE)),
            "{err_string}"
        );

        // wrong scalar value with correct length
        let bad = vec![0xFFu8; G::SCALAR_SIZE];
        let bad_b64 = Base64UrlUnpadded::encode_string(&bad);
        json.as_object_mut()
            .unwrap()
            .insert("scalar".into(), bad_b64.into());
        let err = serde_json::from_value::<TestObject<G>>(json).unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("bytes do not represent a group scalar"),
            "{err_string}"
        );
    }

    #[test]
    fn point_helper_invalid_point() {
        let object: TestObject<G> = TestObject::sample();
        let mut json = serde_json::to_value(object).unwrap();

        // too short: "test" -> 4 bytes
        json.as_object_mut()
            .unwrap()
            .insert("point".into(), "dGVzdA".into());

        let err = serde_json::from_value::<TestObject<G>>(json.clone()).unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("invalid length 4")
                && err_string.contains(&format!("expected {}", G::POINT_SIZE)),
            "{err_string}"
        );

        // wrong point value with correct length
        let bad = vec![0xFFu8; G::POINT_SIZE];
        let bad_b64 = Base64UrlUnpadded::encode_string(&bad);
        json.as_object_mut()
            .unwrap()
            .insert("point".into(), bad_b64.into());
        let err = serde_json::from_value::<TestObject<G>>(json).unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("bytes do not represent a group point"),
            "{err_string}"
        );
    }

    #[test]
    fn vec_helper_invalid_length() {
        let object: TestObject<G> = TestObject::sample();
        let mut json = serde_json::to_value(object).unwrap();
        let more_scalars = &mut json.as_object_mut().unwrap()["more_scalars"];
        more_scalars.as_array_mut().unwrap().pop();

        let err = serde_json::from_value::<TestObject<G>>(json).unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("invalid length 1, expected at least 2 group scalars"),
            "{err_string}"
        );
    }
}

// endregion: --- Tests
