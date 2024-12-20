// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
use grammers_crypto::DequeBuffer;

use super::{Error, Transport, UnpackedOffset};

/// An obfuscation protocol made by telegram to avoid ISP blocks.
/// This is needed to connect to the Telegram servers using websockets or
/// when conecting to MTProto proxies (not yet supported).
///
/// It is simply a wrapper around another transport, which encrypts the data
/// using AES-256-CTR with a randomly generated key that is then sent at the
/// beginning of the connection.
///
/// Obfuscated transport is not meant to be nested or used with "untagged"
/// transports such as `Full`. It will panic if you try to do so.
///
/// [Transport Obfuscation](https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation)
pub struct Obfuscated<T: Transport> {
    inner: T,
    head: Option<[u8; 64]>,
    rx_cipher: ctr::Ctr128BE<aes::Aes256>,
    tx_cipher: ctr::Ctr128BE<aes::Aes256>,
}

const FORBIDDEN_FIRST_INTS: [[u8; 4]; 9] = [
    [0x44, 0x41, 0x45, 0x48],
    [0x54, 0x53, 0x4f, 0x50],
    [0x20, 0x54, 0x45, 0x47],
    [0x49, 0x54, 0x50, 0x4f],
    [0x02, 0x01, 0x03, 0x16],
    [0xdd, 0xdd, 0xdd, 0xdd],
    [0xee, 0xee, 0xee, 0xee],
    [0x50, 0x4f, 0x53, 0x54],
    [0x47, 0x45, 0x54, 0x20],
];

impl<T: Transport> Obfuscated<T> {
    fn generate_keys(
        inner: &mut T,
    ) -> (
        [u8; 64],
        ctr::Ctr128BE<aes::Aes256>,
        ctr::Ctr128BE<aes::Aes256>,
    ) {
        let mut init = [0; 64];

        while init[4..8] == [0; 4]
            || init[0] == 0xef
            || FORBIDDEN_FIRST_INTS.iter().any(|start| start == &init[..4])
        {
            getrandom::getrandom(&mut init).unwrap();
        }

        init[56..60].copy_from_slice(inner.obfuscated_tag());

        let init_rev = init.iter().copied().rev().collect::<Vec<_>>();

        let rx_cipher = ctr::Ctr128BE::<aes::Aes256>::new(
            GenericArray::from_slice(&init_rev[8..40]),
            GenericArray::from_slice(&init_rev[40..56]),
        );

        let mut tx_cipher = ctr::Ctr128BE::<aes::Aes256>::new(
            GenericArray::from_slice(&init[8..40]),
            GenericArray::from_slice(&init[40..56]),
        );

        let mut encrypted_init = init.to_vec();
        tx_cipher.apply_keystream(&mut encrypted_init);

        init[56..64].copy_from_slice(&encrypted_init[56..64]);

        (init, rx_cipher, tx_cipher)
    }
    pub fn new(mut inner: T) -> Self {
        let (init, rx_cipher, tx_cipher) = Self::generate_keys(&mut inner);

        Self {
            inner,
            head: Some(init),
            rx_cipher,
            tx_cipher,
        }
    }
}

impl<T: Transport> Transport for Obfuscated<T> {
    fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        self.inner.pack(buffer);
        self.tx_cipher.apply_keystream(&mut buffer.as_mut());
        if let Some(head) = self.head.take() {
            buffer.extend_front(&head);
        }
    }

    fn unpack(&mut self, buffer: &[u8]) -> Result<UnpackedOffset, Error> {
        self.inner.unpack(buffer)
    }

    fn reset(&mut self) {
        self.inner.reset();
        let (init, rx_cipher, tx_cipher) = Self::generate_keys(&mut self.inner);

        self.head = Some(init);
        self.rx_cipher = rx_cipher;
        self.tx_cipher = tx_cipher;
    }

    fn obfuscated_tag(&mut self) -> &[u8; 4] {
        unreachable!("obfuscated transport cannot be nested")
    }

    fn deobfuscate(&mut self, buffer: &mut [u8]) {
        self.rx_cipher.apply_keystream(buffer);
    }
}
