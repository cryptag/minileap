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
math.log2(1296 ** 25) == 258.49625007211563  # ~258.5 bits of entropy, plus we use scrypt for memory-hard key stretching
```


#### Message Structure

What gets encrypted:

`[ header (see below) || header HMAC (blake2b of 32-byte symmetric encryption key header's nonce + ciphertext) || (24-byte nonce + chunk 1 of the size indicated in the header + blake2b(previous blake2b (rolling) + nonce + ciphertext in this chunk) || 24-byte nonce + chunk 2 + blake2b(...) ) || sha512(key || all previous contents (nonce + ciphertext + blake2b hash per chunk)) to mark the end ]`

The 6-byte header:

`[ 4 bytes: chunk size (uint32, big endian) || 2 bytes: message type (uint16, big endian) (see below) ]`

Min permitted chunk size: 1,000 bytes (consider choosing ~64kb if you need random access (to download/decrypt less data), ~1mb if you don't (to perform fewer encryptions/decryptions))

Max chunk size: 256**4 - 1 bytes == 4,294,967,295 == ~4.3GB

Total possible miniLeap message types: 256**2 == 65,536


#### Message Types

0: (Invalid type; sanity check)

1: UTF-8 encoded text (e.g., chat message)

2: URL, including the protocol (e.g., https://leapchat.org, not just leapchat.org)

3: A command to execute

4: Passphrase (first and only non-header chunk is 256 bytes: 1 uint8 to tell us the passphrase length L (must be at least 75), then L bytes of passphrase, then `255 - L` random bytes of padding)

5: File (first non-header chunk is 256 bytes before encryption: 1 uint8 to tell us the filename length L, then L bytes, then `255 - L` bytes of random byte padding; remaining chunks use the scheme described above, namely 1+ chunks of nonce-prefixed ciphertext)

6 through 65,535: Reserved for future assignment; please submit a PR to propose a new message type


#### Future Enhancements Under Consideration

None!  K.I.S.S.


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


#### What is the overhead if I want to encrypt a tiny, 1-byte chat message?

In general, the overhead of encrypting data with miniLeap is 104 bytes/chunk + 173 bytes (for header and trailing hash).

If you're encrypting 1,000,000 bytes, all in one chunk, the resulting
ciphertext is thus 1,000,277 bytes (0.0277% overhead).

If you're encrypting 100 bytes, all in one chunk, the resulting
ciphertext is 377 bytes (277% overhead).

If you're encrypting just 1 byte, the resulting ciphertext is 277
bytes (27,600% overhead, which sounds big, but in absolute terms
that's just 252 bytes of overhead -- well worth the price of a simple
spec and thus a simple implementation in many programming languages).

`[ header (109 bytes) || chunk 1 (105 total bytes, 1 byte of content and 104 bytes of overhead) || sha512 HMAC (64 bytes) ]`

header: `[ 24-byte nonce || 5-byte body + 16-byte authentication tag || 64-byte blake2b HMAC ]`

chunk 1: `[ 24-byte nonce || 1-byte body + 16-byte authentication tag || 64-byte blake2b HMAC ]`

sha512 HMAC: `[ 64-byte sha512 hash ]`
