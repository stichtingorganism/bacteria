// Copyright 2019 Stichting Organism
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

//! Implementation of  Strobe.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use crate::internal::{
    AlignedKeccakState,
    SPONGE_BLOCK_SIZE,
    keccakf_u8
};

/// Strobe R value; security level 128 is hardcoded
/// 128 used here as we are using 128 bit varient
/// let sec = 128;
/// let rate = SPONGE_BLOCK_SIZE * 8 - (sec as usize) / 4 - 2;
const STROBE_R: usize = 166;

/// The size of the authentication tag used in AEAD functions
pub const MACLEN: usize = 16; //bytes 


/// An empty struct that just indicates that an error occurred in verifying a MAC
#[derive(Debug)]
pub struct AuthError;

//
// Operation flags defined in the Strobe paper.
//

/// Is data being moved inbound
const FLAG_I: u8 = 1;
/// Is data being sent to the application
const FLAG_A: u8 = 1 << 1;
/// Does this operation use cipher output
const FLAG_C: u8 = 1 << 2;
/// Is data being sent for transport
const FLAG_T: u8 = 1 << 3;
/// Use exclusively for metadata operations
const FLAG_M: u8 = 1 << 4;
/// Reserved and currently unimplemented. Using this will cause a panic.
const FLAG_K: u8 = 1 << 5;




/// A Strobe context for the 128-bit security level.
#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct Strobe128 {
    /// Internal Keccak state
    pub(crate) state: AlignedKeccakState,
    /// Index into `state`
    pos: usize,
    /// Index into `state`
    pos_begin: usize,
    // /// Byte that stores the protocol flags
    // cur_flags: u8,
    /// Represents whether we're a sender or a receiver or uninitialized
    is_receiver: Option<bool>,
}

impl ::core::fmt::Debug for Strobe128 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        // Ensure that the Strobe state isn't accidentally logged
        write!(f, "Strobe128: STATE OMITTED")
    }
}


impl Strobe128 {

    /// Makes a new `Strobe` object with a given protocol byte string and with security parameter 128bit.
    pub fn new(protocol_label: &[u8]) -> Strobe128 {
       
        // Initialize state: st = F([0x01, R+2, 0x01, 0x00, 0x01, 0x60] + b"STROBEvX.Y.Z")
        let initial_state = {
            let mut st = AlignedKeccakState([0u8; 200]);
            st[0..6].copy_from_slice(&[0x01, (STROBE_R + 2) as u8, 0x01, 0x00, 0x01, 0x60]);
            st[6..18].copy_from_slice(b"STROBEv1.0.2");
            keccakf_u8(&mut st);

            st
        };

        let mut strobe = Strobe128 {
            state: initial_state,
            pos: 0,
            pos_begin: 0,
            //cur_flags: 0,
            is_receiver: None,
        };

        // Mix the protocol into the state
        strobe.meta_ad(protocol_label, false);

        strobe
    }

    pub fn set_as_receiver(&mut self) {
        self.is_receiver = Some(true);
    }

    pub fn set_as_sender(&mut self) {
        self.is_receiver = Some(false);
    }

    /// Runs the permutation function on the internal state
    fn run_f(&mut self) {
        self.state[self.pos] ^= self.pos_begin as u8;
        self.state[self.pos + 1] ^= 0x04;
        self.state[STROBE_R + 1] ^= 0x80;
        keccakf_u8(&mut self.state);
        self.pos = 0;
        self.pos_begin = 0;
    }

    /// XORs the given data into the state. This is a special case of the `duplex` code in the
    /// STROBE paper.
    fn absorb(&mut self, data: &[u8]) {
        for byte in data {
            self.state[self.pos] ^= byte;

            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    /// XORs the given data into the state, then sets the data equal the state.  This is a special
    /// case of the `duplex` code in the STROBE paper.
    fn absorb_and_set(&mut self, data: &mut [u8]) {
        for byte in data {
            let state_byte = self.state.get_mut(self.pos).unwrap();

            *state_byte ^= *byte;
            *byte = *state_byte;

            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    /// Copies the internal state into the given buffer. This is a special case of `absorb_and_set`
    /// where `data` is all zeros.
    fn copy_state(&mut self, data: &mut [u8]) {
        for byte in data {
            *byte = self.state[self.pos];

            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    /// Overwrites the state with the given data while XORing the given data with the old state.
    /// This is a special case of the `duplex` code in the STROBE paper.
    fn exchange(&mut self, data: &mut [u8]) {
        for byte in data {
            let state_byte = self.state.get_mut(self.pos).unwrap();
            *byte ^= *state_byte;
            *state_byte ^= *byte;

            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    /// Overwrites the state with the given data. This is a special case of `Strobe::exchange`,
    /// where we do not want to mutate the input data.
    fn overwrite(&mut self, data: &[u8]) {
        for byte in data {
            self.state[self.pos] = *byte;

            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    /// Copies the state into the given buffer and sets the state to 0. This is a special case of
    /// `Strobe::exchange`, where `data` is assumed to be the all-zeros string. This is precisely
    /// the case when the current operation is PRF.
    fn squeeze(&mut self, data: &mut [u8]) {
        for byte in data {
            *byte = self.state[self.pos];
            self.state[self.pos] = 0;

            self.pos += 1;
            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }

    /// Overwrites the state with a specified number of zeros. This is a special case of
    /// `Strobe::exchange`. More specifically, it's a special case of `Strobe::overwrite` and
    /// `Strobe::squeeze`. It's like `squeeze` in that we assume we've been given all zeros as
    /// input, and like `overwrite` in that we do not mutate (or take) any input.
    fn zero_state(&mut self, mut bytes_to_zero: usize) {
        static ZEROS: [u8; 8 * SPONGE_BLOCK_SIZE] = [0u8; 8 * SPONGE_BLOCK_SIZE];

        // Do the zero-writing in chunks
        while bytes_to_zero > 0 {

            let slice_len = core::cmp::min(STROBE_R - self.pos, bytes_to_zero);
            self.state[self.pos..(self.pos + slice_len)].copy_from_slice(&ZEROS[..slice_len]);

            self.pos += slice_len;
            bytes_to_zero -= slice_len;

            if self.pos == STROBE_R {
                self.run_f();
            }
        }
    }


    /// Performs the state / data transformation that corresponds to the given flags. 
    fn begin_op(&mut self, mut flags: u8) {
        // Accounting for whether we are sending or receiving.
        if flags & FLAG_T == FLAG_T {
            // inbound data ?
            let is_op_receiving = (flags & FLAG_I) == FLAG_I;

            // If uninitialized, take on the direction of the first directional operation we get
            if self.is_receiver.is_none() {
                self.is_receiver = Some(is_op_receiving);
            }

            // So that the sender and receiver agree, toggle the I flag as necessary
            if self.is_receiver.unwrap() != is_op_receiving {
                //insert
                flags |= FLAG_I;
            } else {
                //remove
                flags &= !FLAG_I;
            }
        }
        
        // Mixes the current state index and flags into the state
        let old_begin = self.pos_begin as u8;
        self.pos_begin = self.pos + 1;
        //self.cur_flags = flags;

        self.absorb(&[old_begin, flags]);

        // Force running F if C or K is set
        let force_f = 0 != (flags & (FLAG_C | FLAG_K));

        if force_f && self.pos != 0 {
            self.run_f();
        }
    }
    
    // TODO?: Keep track of cur_flags and assert they don't change when `more` is set
    /// Performs the state transformation that corresponds to the given flags. 
    /// This uses non-mutating variants of the specializations of the `duplex` function.
    /// If `more` is given, this will treat `data` as a continuation of the data
    /// given in the previous call to `begin_op`.
    fn operate_mut(&mut self, flags: u8, data: &mut [u8], more: bool) {
        assert!(!((flags & FLAG_K) == FLAG_K), "Op flag K not implemented");

        // Check if we're continuing an operation
        if !more {
            self.begin_op(flags);
        }
        
        // Meta-ness is only relevant for `begin_op`. Remove it to simplify the below logic.
        let flags = flags & !FLAG_M;

        // TODO?: Assert that input is empty under some flag conditions
        if ((flags & FLAG_C) == FLAG_C) && ((flags & FLAG_T) == FLAG_T) && !((flags & FLAG_I) == FLAG_I) {
            // This is equivalent to the `duplex` operation in the Python implementation, with
            // `cafter = True`
            if flags == FLAG_C | FLAG_T {
                // This is `send_mac`. Pretend the input is all zeros
                self.copy_state(data)
            } else {
                self.absorb_and_set(data);
            }
            
        } else if flags == FLAG_I | FLAG_A | FLAG_C {
            // Special case of case below. This is PRF. Use `squeeze` instead of `exchange`.
            self.squeeze(data);

        } else if (flags & FLAG_C) == FLAG_C {
            // This is equivalent to the `duplex` operation in the Python implementation, with
            // `cbefore = True`
            self.exchange(data);

        } else {
            // This should normally call `absorb`, but `absorb` does not mutate, so the implementor
            // should have used operate_no_mutate instead
            panic!("operate should not be called for operations that do not require mutation");
        }
        
    }

    /// Performs the state transformation that corresponds to the given flags. 
    fn operate(&mut self, flags: u8, data: &[u8], more: bool) {
        assert!(!((flags & FLAG_K) == FLAG_K), "Op flag K not implemented");

        // Check if we're continuing an operation
        if !more {
            self.begin_op(flags);
        }
        
        // There are no non-mutating variants of things with flags & (C | T | I) == C | T
        if ((flags & FLAG_C) == FLAG_C) && ((flags & FLAG_T) == FLAG_T) && !((flags & FLAG_I) == FLAG_I) {
            panic!("operate_no_mutate called on something that requires mutation");

        } else if (flags & FLAG_C) == FLAG_C {

            // This is equivalent to a non-mutating form of the `duplex` operation in the Python
            // implementation, with `cbefore = True`
            self.overwrite(data);
        } else {
            // This is equivalent to the `duplex` operation in the Python implementation, with
            // `cbefore = cafter = False`
            self.absorb(data);
        };
        
    }

    // This is separately defined because it's the only method that can return a `Result`. See docs
    // for recv_mac and meta_recv_mac.
    fn generalized_recv_mac(
        &mut self,
        data: &mut [u8],
        more: bool,
        is_meta: bool,
    ) -> Result<(), AuthError> {

        // These are the (meta_)recv_mac flags
        let flags = if is_meta {
            FLAG_I | FLAG_C | FLAG_T | FLAG_M
        } else {
            FLAG_I | FLAG_C | FLAG_T
        };

        self.operate_mut(flags, data, more);

        // Constant-time MAC check. This accumulates the truth values of byte == 0
        let mut all_zero = subtle::Choice::from(1u8);
        
        for b in data {
            all_zero = all_zero & b.ct_eq(&0u8);
        }

        if all_zero.unwrap_u8() != 1 {
            Err(AuthError)
        } else {
            Ok(())
        }
    }

    /// Attempts to authenticate the current state against the given MAC. On failure, it returns an
    /// `AuthError`. It behooves the user of this library to check this return value and overreact
    /// on error.
    pub fn recv_mac(&mut self, data: &mut [u8], more: bool) -> Result<(), AuthError> {
        self.generalized_recv_mac(data, more, /* is_meta */ false)
    }

    /// Attempts to authenticate the current state against the given MAC. On failure, it returns an
    /// `AuthError`. It behooves the user of this library to check this return value and overreact
    /// on error.
    pub fn meta_recv_mac(&mut self, data: &mut [u8], more: bool) -> Result<(), AuthError> {
        self.generalized_recv_mac(data, more, /* is_meta */ true)
    }

    // This is separately defined because it's the only method that takes an integer and mutates
    // its input
    fn generalized_ratchet(&mut self, num_bytes_to_zero: usize, more: bool, is_meta: bool) {
        // These are the (meta_)ratchet flags
        let flags = if is_meta {
            FLAG_C | FLAG_M
        } else {
            FLAG_C
        };

        // We don't make an `operate` call, since this is a super special case. That means we have
        // to make the `begin_op` call manually.
        if !more {
            self.begin_op(flags);
        }

        self.zero_state(num_bytes_to_zero);
    }

    /// Ratchets the internal state forward in an irreversible way by zeroing bytes.
    ///
    /// Takes a `usize` argument specifying the number of bytes of public state to zero. If the
    /// size exceeds `self.rate`, Keccak-f will be called before more bytes are zeroed.
    pub fn ratchet(&mut self, num_bytes_to_zero: usize, more: bool) {
        self.generalized_ratchet(num_bytes_to_zero, more, /* is_meta */ false)
    }

    /// Ratchets the internal state forward in an irreversible way by zeroing bytes.
    ///
    /// Takes a `usize` argument specifying the number of bytes of public state to zero. If the
    /// size exceeds `self.rate`, Keccak-f will be called before more bytes are zeroed.
    pub fn meta_ratchet(&mut self, num_bytes_to_zero: usize, more: bool) {
        self.generalized_ratchet(num_bytes_to_zero, more, /* is_meta */ true)
    }


    //
    // These operations mutate their inputs
    //

    /// Sends an encrypted message.
    pub fn send_enc(&mut self, data: &mut [u8], more: bool) {
        let flags = FLAG_A | FLAG_C | FLAG_T;
        self.operate_mut(flags, data, more);
    }

    /// Sends an encrypted message.
    pub fn meta_send_enc(&mut self, data: &mut [u8], more: bool) {
        let flags = FLAG_A | FLAG_C | FLAG_T | FLAG_M;
        self.operate_mut(flags, data, more);
    }

    /// Receives an encrypted message.
    pub fn recv_enc(&mut self, data: &mut [u8], more: bool) {
        let flags = FLAG_I | FLAG_A | FLAG_C | FLAG_T;
        self.operate_mut(flags, data, more);
    }

    /// Receives an encrypted message.
    pub fn meta_recv_enc(&mut self, data: &mut [u8], more: bool) {
        let flags = FLAG_I | FLAG_A | FLAG_C | FLAG_T | FLAG_M;
        self.operate_mut(flags, data, more);
    }

    /// Sends a MAC of the internal state. The output is independent of the initial contents of the input buffer.
    pub fn send_mac(&mut self, data: &mut [u8], more: bool) {
        let flags = FLAG_C | FLAG_T;
        self.operate_mut(flags, data, more);
    }

    /// Sends a MAC of the internal state. The output is independent of the initial contents of the input buffer.
    pub fn meta_send_mac(&mut self, data: &mut [u8], more: bool) {
        let flags = FLAG_C | FLAG_T | FLAG_M;
        self.operate_mut(flags, data, more);
    }


    /// Extracts pseudorandom data as a function of the internal state.
    /// The output is independent of the initial contents of the input buffer.    
    pub fn prf(&mut self, data: &mut [u8], more: bool) {
        let flags = FLAG_I | FLAG_A | FLAG_C;
        self.operate_mut(flags, data, more);
    }

    /// Extracts pseudorandom data as a function of the internal state.
    /// The output is independent of the initial contents of the input buffer.
    pub fn meta_prf(&mut self, data: &mut [u8], more: bool) {
        let flags = FLAG_I | FLAG_A | FLAG_C | FLAG_M;
        self.operate_mut(flags, data, more);
    }

  
    //
    // These operations do not mutate their inputs
    //

    /// Sends a plaintext message.
    pub fn send_clr(&mut self, data: &[u8], more: bool) {
        let flags = FLAG_A | FLAG_T;
        self.operate(flags, data, more);
    }

    /// Sends a plaintext message.
    pub fn meta_send_clr(&mut self, data: &[u8], more: bool) {
        let flags = FLAG_A | FLAG_T | FLAG_M;
        self.operate(flags, data, more);
    }

    /// Receives a plaintext message.
    pub fn recv_clr(&mut self, data: &[u8], more: bool) {
        let flags = FLAG_I | FLAG_A | FLAG_T;
        self.operate(flags, data, more);
    }

    /// Receives a plaintext message.
    pub fn meta_recv_clr(&mut self, data: &[u8], more: bool) {
        let flags = FLAG_I | FLAG_A | FLAG_T | FLAG_M;
        self.operate(flags, data, more);
    }

    /// Mixes associated data into the internal state.
    pub fn ad(&mut self, data: &[u8], more: bool) {
        let flags = FLAG_A;
        self.operate(flags, data, more);
    }

    /// Mixes associated data into the internal state.
    pub fn meta_ad(&mut self, data: &[u8], more: bool) {
        let flags = FLAG_A | FLAG_M;
        self.operate(flags, data, more);
    }

    /// Sets a symmetric cipher key.
    pub fn key(&mut self, data: &[u8], more: bool) {
        let flags = FLAG_A | FLAG_C;
        self.operate(flags, data, more);
    }

    /// Sets a symmetric cipher key.
    pub fn meta_key(&mut self, data: &[u8], more: bool) {
        let flags = FLAG_A | FLAG_C | FLAG_M;
        self.operate(flags, data, more);
    }

    //
    // AEAD
    //

    /// encrypt data and authenticate additional data
    pub fn send_aead(&mut self, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let mut ciphertext = plaintext.to_vec();
        // Encrypt
        self.send_enc(ciphertext.as_mut_slice(), false);
        // authenticate data
        self.ad(ad, false);
        // calc mac
        let mut mac = [0u8; MACLEN];
        self.send_mac(&mut mac[..], false);
        //ciphertext + mac, does not have length information of text at the head
        ciphertext.extend_from_slice(&mac);
        return ciphertext;
    }

    /// decrypt data and authenticate additional data
    pub fn recv_aead(&mut self, ciphertext: &[u8],  ad: &[u8]) -> Result<Vec<u8>, AuthError>{
        if ciphertext.len() < MACLEN {
            return Err(AuthError);
	    }
        let mut plaintext = ciphertext.to_vec();
        let mut mac = plaintext.split_off(plaintext.len() - MACLEN);

        //decrypt
        self.recv_enc(plaintext.as_mut_slice(), false);
        // authenticate data
        self.ad(ad, false);
        // verify mac
        let verify_res = self.recv_mac(&mut mac[..], false);

        if verify_res.is_ok() {
            return Ok(plaintext);
        } else {
            return Err(AuthError);
        }
    }

}



