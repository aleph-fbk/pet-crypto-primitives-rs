//! (De)Serialization with serde.

use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};

use dlog_group::{group::Group, serde::*};

use crate::elgamal::ciphertext::Ciphertext;

/// Helper type to deserialize Ciphertexts.
#[derive(Debug)]
pub struct CiphertextHelper<G: Group>(Ciphertext<G>);

impl<G: Group> CiphertextHelper<G> {
    pub fn serialize<S>(ciphertext: &Ciphertext<G>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = Ciphertext::<G>::to_bytes(ciphertext);
        serialize_bytes(&bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ciphertext<G>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_bytes(deserializer)?;
        if bytes.len() == 3 * G::POINT_SIZE {
            Ciphertext::<G>::from_bytes(&bytes)
                .ok_or_else(|| D::Error::custom("bytes do not represent an elgamal ciphertext"))
        } else {
            let expected_len = (3 * G::POINT_SIZE).to_string();
            Err(D::Error::invalid_length(
                bytes.len(),
                &expected_len.as_str(),
            ))
        }
    }
}

impl<G: Group> Serialize for CiphertextHelper<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(&self.0, serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for CiphertextHelper<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::deserialize(deserializer).map(Self)
    }
}

impl<G: Group> Helper for CiphertextHelper<G> {
    const PLURAL_DESCRIPTION: &'static str = "elgamal ciphertexts";
    type Target = Ciphertext<G>;

    fn from_target(target: &Self::Target) -> Self {
        Self(*target)
    }

    fn into_target(self) -> Self::Target {
        self.0
    }
}

// /// Helper type to deserialize a Zero Proof.
// #[derive(Debug)]
// pub struct ZeroHelper<G: Group>(Zero<G>);

// impl<G: Group> ZeroHelper<G> {
//     pub fn serialize<S>(zero: Zero<G>, serializer: S) -> Result<S::Ok,
// S::Error>     where
//         S: Serializer,
//     {
//         let bytes = Zero::<G>::to_bytes(zero);
//         serialize_bytes(&bytes, serializer)
//     }

//     pub fn deserialize<'de, D>(deserializer: D) -> Result<Zero<G>, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let bytes = deserialize_bytes(deserializer)?;
//         if bytes.len() == 3 * G::POINT_SIZE + G::SCALAR_SIZE {
//             Zero::<G>::from_bytes(&bytes)
//                 .ok_or_else(|| D::Error::custom("bytes do not represent a
// zero proof"))         } else {
//             let expected_len = (3 * G::POINT_SIZE +
// G::SCALAR_SIZE).to_string();             Err(D::Error::invalid_length(
//                 bytes.len(),
//                 &expected_len.as_str(),
//             ))
//         }
//     }
// }

// impl<G: Group> Serialize for ZeroHelper<G> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         Self::serialize(self.0, serializer)
//     }
// }

// impl<'de, G: Group> Deserialize<'de> for ZeroHelper<G> {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         Self::deserialize(deserializer).map(Self)
//     }
// }

// impl<G: Group> Helper for ZeroHelper<G> {
//     const PLURAL_DESCRIPTION: &'static str = "zero proof";
//     type Target = Zero<G>;

//     fn from_target(target: &Self::Target) -> Self {
//         Self(*target)
//     }

//     fn into_target(self) -> Self::Target {
//         self.0
//     }
// }

// // region:    --- Tests

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use dlog_group::{group::GroupPoint, ristretto::RistrettoGroup};

//     #[derive(Debug, PartialEq, Serialize, Deserialize)]
//     #[serde(bound = "")]
//     struct TestObject<G: Group> {
//         // TestObject to simulate a NIZKP serialization
//         #[serde(with = "CiphertextHelper::<G>")]
//         commitment: Ciphertext<G>,
//         #[serde(with = "ScalarHelper::<G>")]
//         response: G::Scalar,
//     }

//     impl TestObject<RistrettoGroup> {
//         fn sample() -> Self {
//             let mut rng = rand::thread_rng();
//             Self {
//                 commitment: Ciphertext {
//                     random_point: RistrettoGroup::point_random(&mut rng),
//                     random_point2: RistrettoGroup::point_random(&mut rng),
//                     blinded_point: RistrettoGroup::point_random(&mut rng),
//                 },
//                 response: 12345_u64.into(),
//             }
//         }
//     }

//     #[test]
//     fn helpers_roundtrip() {
//         let object = TestObject::sample();
//         let json = serde_json::to_value(&object).unwrap();
//         let object_copy: TestObject<RistrettoGroup> =
// serde_json::from_value(json).unwrap();         assert_eq!(object_copy,
// object);     }

//     #[test]
//     fn scalar_helper_invalid_scalar() {
//         let object = TestObject::sample();
//         let mut json = serde_json::to_value(object).unwrap();
//         json.as_object_mut()
//             .unwrap()
//             .insert("response".into(), "dGVzdA".into());

//         let err =
// serde_json::from_value::<TestObject<RistrettoGroup>>(json.clone()).
// unwrap_err();         let err_string = err.to_string();
//         assert!(
//             err_string.contains("invalid length 4, expected 32"),
//             "{err_string}"
//         );

//         json.as_object_mut().unwrap().insert(
//             "response".into(),
//             "nN3xf7lSOX0_zs6QPBwWHYi0Dkx2Ln_z1MPwnbzaM_8".into(),
//         );
//         let err =
// serde_json::from_value::<TestObject<RistrettoGroup>>(json).unwrap_err();
//         let err_string = err.to_string();
//         assert!(
//             err_string.contains("bytes do not represent a group scalar"),
//             "{err_string}"
//         );
//     }

//     #[test]
//     fn ciphertext_helper_invalid_ciphertext() {
//         let object = TestObject::sample();
//         let mut json = serde_json::to_value(object).unwrap();
//         json.as_object_mut()
//             .unwrap()
//             .insert("commitment".into(), "dGVzdA".into());

//         println!("{json}");

//         let err =
// serde_json::from_value::<TestObject<RistrettoGroup>>(json.clone()).
// unwrap_err();         let err_string = err.to_string();
//         assert!(
//             err_string.contains("invalid length 4, expected 96"),
//             "{err_string}"
//         );

//         json.as_object_mut().unwrap().insert(
//             "commitment".into(),
//
// "inDsLc3BWFBbJbmlEaijZGRtfPQIranGAzwqHcXPDWIYbrPOTUIbbNzAtEZoER_98TQu-zBimgl5sC2vVFOeX8BnoNfUMV-SD6IGEnsdkJ6dEHt4MUGKVrXSI1rSc2Qz"
// .into(),         );
//         let err =
// serde_json::from_value::<TestObject<RistrettoGroup>>(json).unwrap_err();
//         let err_string = err.to_string();
//         assert!(
//             err_string.contains("bytes do not represent an elgamal
// ciphertext"),             "{err_string}"
//         );
//     }
// }

// // endregion: --- Tests
