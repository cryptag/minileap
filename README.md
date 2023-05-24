# miniLeap

#### Design

All data is encrypted using libsodium's secretbox.  Each chunk
consists of a 24-byte nonce followed by data encrypted using a
symmetric key seeded with the private half of a curve25519 keypair.
This keypair is derived using the same scheme used by LeapChat: by
randomly choosing 25 words from
[this](https://github.com/cryptag/leapchat/blob/c1036ae1eaeb86b9cbdc266fbe309e611b411463/src/data/effWordlist.js)
EFF-created word list (consisting of 1296 words).


```python
import math
math.log2(1296 ** 25) == 258.49625007211563  # ~258.5 bits of entropy, plus there's memory-hard key stretching
```

#### Message Structure

What gets encrypted:

`[ header (see below) || 1+ chunks of the size indicated in the header || sha512(all previous contents (nonce + ciphertext) || key) ]`

The 4-byte header:

`[ 3 bytes: chunk size (uint8, big endian) || 1 byte: message type (uint8) ]`

Max chunk size: 2**(3*8) bytes == 2**24 bytes == 16,777,216 bytes == ~16mb


#### Message Types

0: (Invalid type; sanity check)

1: File (first non-header chunk is 256 bytes: 1 uint8 to tell us the file length L, then L bytes, then `255 - L` bytes of random byte padding; remaining chunks use the scheme described above, namely 1+ chunks of nonce-prefixed ciphertext)

2: Passphrase (first and only non-header chunk is 256 bytes: 1 uint8 to tell us the passphrase length L, then L bytes of passphrase, then `255 - L` random bytes of padding)

3-255: Reserved for future assignment


#### Future Enhancements Under Consideration

How to store decoy files:

`[ 8 bytes (cryptographically ignored) || 3 bytes (chunk size, big endian) || 1+ chunks of that size || sha512(all previous contents || key) ]`

The leading 8 bytes are reserved for magic number that matches
apparent file type.  This is so we can disguise our encrypted data as
arbitrary data types without changing the ciphertext.


## FAQ

#### Why not use secretstream?

Because neither Go implementation I tried worked at all, neither the
one that used CGo to wrap libsodium nor a Go native one.  So I made
this library to suit my needs.


#### Why not use `github.com/dchest/nacl-stream-js` or similar?

Because we need random access which, as the end of agl's blog post
points out, this scheme does not allow.  Also, we don't want
regularities in the ciphertext, such as a monotonically increasing
chunk number occurring at regular intervals.


#### Wouldn't it be better to not just have one MAC at the end?

I am not aware of a simple way to (1) preserve random access (once the
chunk size is known), (2) MAC each chunk... hmmmmm...
