// Copyright 2021 Stichting Organism
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

#[cfg(not(target_endian = "little"))]
use byteorder::{ByteOrder, LittleEndian};
use zeroize::Zeroize;
use std::ops::{Deref, DerefMut};

/// keccak block size in 64-bit words. This is the N parameter in the STROBE spec
pub const SPONGE_BLOCK_SIZE: usize = 25;

/// This is a wrapper around 200-byte buffer that's always 8-byte aligned to make pointers to it
/// safely convertible to pointers to [u64; 25] (since u64 words must be 8-byte aligned)
#[derive(Zeroize, Clone)]
#[repr(align(8))]
#[zeroize(drop)]
pub(crate) struct AlignedKeccakState(pub(crate) [u8; 8 * SPONGE_BLOCK_SIZE]);

/// Performs the keccakf\[1600\] permutation on a byte buffer
// When we're on a little-endian platform, there's no need to copy over the buffer, we can do the
// keccak_f in-place
#[cfg(target_endian = "little")]
pub(crate) fn keccakf_u8(st: &mut AlignedKeccakState) {
    unsafe {
        let mut transmuted_block: &mut [u64; SPONGE_BLOCK_SIZE] = core::mem::transmute(&mut st.0);
        crate::sponge::f1600(&mut transmuted_block);
    }
}

/// Performs the keccakf\[1600\] permutation on a byte buffer
// If we're not little-endian, we can't perform the above optimization. Make a little-endian copy,
// do the operation, then copy the bytes back.
#[cfg(not(target_endian = "little"))]
pub(crate) fn keccakf_u8(st: &mut AlignedKeccakState) {
    let mut keccak_block = [0u64; SPONGE_BLOCK_SIZE];
    LittleEndian::read_u64_into(st.0, &mut keccak_block);
    mohan::sponge::f1600(&mut keccak_block);
    LittleEndian::write_u64_into(&keccak_block, &mut st.0);
}

/*
# The Python 2 code used to generate this test vector is below. For more information on how to
# get this code running, look at the comment at the top # of `basic_tests.rs`
from Strobe.Keccak import KeccakF
k = KeccakF()
out = k([0]*200)
print("[{}]".format(', '.join(map("0x{:02x}".format, out))))
*/
#[test]
fn zero_keccak() {
    let mut state = AlignedKeccakState([0u8; 8 * SPONGE_BLOCK_SIZE]);
    keccakf_u8(&mut state);
    let expected_output = [
        0xe7, 0xdd, 0xe1, 0x40, 0x79, 0x8f, 0x25, 0xf1, 0x8a, 0x47, 0xc0, 0x33, 0xf9, 0xcc, 0xd5,
        0x84, 0xee, 0xa9, 0x5a, 0xa6, 0x1e, 0x26, 0x98, 0xd5, 0x4d, 0x49, 0x80, 0x6f, 0x30, 0x47,
        0x15, 0xbd, 0x57, 0xd0, 0x53, 0x62, 0x05, 0x4e, 0x28, 0x8b, 0xd4, 0x6f, 0x8e, 0x7f, 0x2d,
        0xa4, 0x97, 0xff, 0xc4, 0x47, 0x46, 0xa4, 0xa0, 0xe5, 0xfe, 0x90, 0x76, 0x2e, 0x19, 0xd6,
        0x0c, 0xda, 0x5b, 0x8c, 0x9c, 0x05, 0x19, 0x1b, 0xf7, 0xa6, 0x30, 0xad, 0x64, 0xfc, 0x8f,
        0xd0, 0xb7, 0x5a, 0x93, 0x30, 0x35, 0xd6, 0x17, 0x23, 0x3f, 0xa9, 0x5a, 0xeb, 0x03, 0x21,
        0x71, 0x0d, 0x26, 0xe6, 0xa6, 0xa9, 0x5f, 0x55, 0xcf, 0xdb, 0x16, 0x7c, 0xa5, 0x81, 0x26,
        0xc8, 0x47, 0x03, 0xcd, 0x31, 0xb8, 0x43, 0x9f, 0x56, 0xa5, 0x11, 0x1a, 0x2f, 0xf2, 0x01,
        0x61, 0xae, 0xd9, 0x21, 0x5a, 0x63, 0xe5, 0x05, 0xf2, 0x70, 0xc9, 0x8c, 0xf2, 0xfe, 0xbe,
        0x64, 0x11, 0x66, 0xc4, 0x7b, 0x95, 0x70, 0x36, 0x61, 0xcb, 0x0e, 0xd0, 0x4f, 0x55, 0x5a,
        0x7c, 0xb8, 0xc8, 0x32, 0xcf, 0x1c, 0x8a, 0xe8, 0x3e, 0x8c, 0x14, 0x26, 0x3a, 0xae, 0x22,
        0x79, 0x0c, 0x94, 0xe4, 0x09, 0xc5, 0xa2, 0x24, 0xf9, 0x41, 0x18, 0xc2, 0x65, 0x04, 0xe7,
        0x26, 0x35, 0xf5, 0x16, 0x3b, 0xa1, 0x30, 0x7f, 0xe9, 0x44, 0xf6, 0x75, 0x49, 0xa2, 0xec,
        0x5c, 0x7b, 0xff, 0xf1, 0xea,
    ];

    assert_eq!(&state.0[..], &expected_output[..]);
}

impl Deref for AlignedKeccakState {
    type Target = [u8; 200];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AlignedKeccakState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
