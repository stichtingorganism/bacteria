// Copyright 2019 Stichting Organism
// Copyright 2018 Michael Rosenberg
// Copyright 2018 Henry de Valence.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Strobe [protocol framework](https://eprint.iacr.org/2017/003.pdf).
//! The Strobe framework is simple and extensible. It is suitable for use as a hash, 
//! authenticated cipher, pseudorandom generator, and as the symmetric component 
//! of a network protocol engine. The cryptography of an operation depends primarily 
//! on that operation’s data flow. Can be used as symmetric encryption, hashing and MAC algorithm.


/// Domain separation label to initialize the STROBE context.
pub const BACTERIA_PROTOCOL_LABEL: &[u8] = b"BACTERIAv0.0.1";


pub(crate) mod internal;
mod strobe;

pub use strobe::{
    Strobe128
};

mod transcript;
pub use transcript::Transcript;
pub use transcript::TranscriptRng;
pub use transcript::TranscriptRngBuilder;

#[cfg(test)]
mod internal_test;

#[cfg(test)]
mod kat_tests;
