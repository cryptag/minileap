# miniLeap

miniLeap is a simple streaming encryption scheme built on
NaCl/libsodium's SecretBox.

#### Design

All data is encrypted using libsodium's SecretBox.  Each chunk
consists of a 24-byte nonce followed by data encrypted using the same
symmetric key, which is created by seeding with the private half of a
shared curve25519 keypair.  This keypair is derived using the same
scheme as LeapChat:

1. Define `passphrase` := 25 randomly chosen words from
[this](https://github.com/cryptag/leapchat/blob/c1036ae1eaeb86b9cbdc266fbe309e611b411463/src/data/effWordlist.js)
EFF-created word list (consisting of 1296 words == 258.5 bits of
entropy before key stretching; see calculation details below)

2. Define `email := sha384(passphrase) + "@cryptag.org"`

3. Pass `email` and `passphrase` to miniLock to derive a curve25519 keypair

4. Under the hood, miniLock derives the keypair using `scrypt(passphrase, email, 17, 8, 32, 1000)`


Aforementioned entropy calculation:

```python
import math

math.log2(1296 ** 25) == 258.49625007211563  # ~258.5 bits of entropy, plus we use scrypt for memory-hard key stretching
```


#### Message Structure

What gets encrypted:

`[ header (see below) ]` and `[ 1+ chunks of size Chunk Size indicated in the header ]`

The final chunk may be below the stated Chunk Size.

The 6-byte **header** (before encryption):

`[ 4 bytes: Chunk Size (int32 (NOT uint32; the left-most bit of the left-most byte must never be set to 1), big endian) || 2 bytes: message type (uint16, big endian) (see below) ]`

Min permitted Chunk Size: 1,024 bytes.  Consider choosing ~64KB if you
need random access (to download/decrypt less data), and ~1MB if you
don't (to perform fewer encryptions/decryptions).  As stated above,
the last chunk may be smaller than this, but the others may not be
(except the header, obviously, which is small and of fixed size).

Max chunk size: (256**4)/2 - 1 bytes == 2,147,483,647 == ~2.15GB

Total possible miniLeap message types: 256**2 == 65,536


#### Message Types

0: (Invalid type; sanity check)

1: UTF-8 encoded text (e.g., chat message)

2: URL, including the protocol (e.g., https://leapchat.org, not just leapchat.org)

3: A command to execute

4: Passphrase (first and only non-header chunk is 256 bytes: 1 uint8 to tell us the passphrase length L (must be at least 75), then L bytes of passphrase, then `255 - L` random bytes of padding)

5: File (first non-header chunk is 256 bytes before encryption: 1 uint8 to tell us the filename length L, then L bytes, then `255 - L` bytes of random byte padding; remaining chunks use the scheme described above, namely 1+ chunks of nonce-prefixed ciphertext)

6: File with file path, not just filename + body (details TBD)

7 through 65,535: Reserved for future assignment; please submit a PR to propose a new message type


#### Future Enhancements Under Consideration

None!  K.I.S.S.


## FAQ

#### Why not use libsodium's secretstream?

Because neither Go implementation I tried worked at all -- neither the
one that uses CGo to wrap libsodium nor a native Go implementation.
This told me that that construction is too complex for mere mortals to
get right, and thus implementing it securely in many programming
languages could take a while.

Plus I don't need some of the additional flexibility that secretstream
provides and that complicates its implementation.  For example, I
don't need to be able to make each individual chunk of arbitrary size;
setting the chunk size just once and using that for every chunk till
EOF is plenty good enough.  Furthermore, secretstream allows for
mid-stream key ratcheting, which I don't need and again complicates
things.  I also don't need to be able to include "additional data"
that is then used when computing the authentication tag.  So I made
miniLeap to keep things simple, meet my unmet needs, and avoid poor
implementations of secretstream while enjoying nearly all of
[its benefits](https://doc.libsodium.org/secret-key_cryptography/secretstream),
namely:

```
This high-level API encrypts a sequence of messages, or a single
message split into an arbitrary number of chunks, using a secret key,
with the following properties:

* Messages cannot be truncated, removed, reordered, duplicated or
  modified without this being detected by the decryption functions.

* The same sequence encrypted twice will produce different
  ciphertexts.

* An authentication tag is added to each encrypted message: stream
  corruption will be detected early, without having to read the stream
  until the end.

* There are no practical limits to the total length of the stream, or
  to the total number of individual messages.
```

Again, these are the benefits of secretstream I don't need and that,
for my use cases, aren't worth the implementation complexity they
introduce, and thus are purposely _not_ guarantees made by miniLeap:

```
* Each message can include additional data (ex: timestamp, protocol
  version) in the computation of the authentication tag.

* Messages can have different sizes.

* Ratcheting: at any point in the stream, it is possible to "forget"
  the key used to encrypt the previous messages, and switch to a new
  key.
```


#### Why not use `github.com/dchest/nacl-stream-js` or similar?

Because we need random access which, as the end of agl's blog post
points out, this scheme does not allow.  Also, we don't want
regularities in the ciphertext, such as a monotonically increasing
chunk number occurring at regular intervals.


#### What is the overhead if I want to encrypt a tiny, 1-byte chat message?

In general, the overhead of encrypting data with miniLeap is 104
bytes/chunk + 173 bytes (for header and trailing hash; see below).

If you're encrypting 1,000,000 bytes, all in one chunk, the resulting
ciphertext is thus 1,000,277 bytes (0.0277% overhead).

If you're encrypting 100 bytes, all in one chunk, the resulting
ciphertext is 377 bytes (277% overhead).

If you're encrypting just 1 byte, the resulting ciphertext is 277
bytes (27,600% overhead, which sounds like a lot, but in absolute
terms that's just 276 bytes of overhead -- well worth the price of a
simple spec and thus a simple implementation in many programming
languages):

`[ header (109 bytes) || chunk 1 (105 total bytes: 1 byte of content and 104 bytes of overhead) || SHA512 HMAC (64 bytes) ]`

header: `[ 24-byte nonce || 5-byte body + 16-byte authentication tag || 64-byte rolling Blake2b HMAC ]`

chunk 1: `[ 24-byte nonce || 1-byte body + 16-byte authentication tag || 64-byte rolling Blake2b HMAC ]`

SHA512 HMAC: `[ 64-byte SHA512 hash ]`

The end result of all this encrypting and hashing is a file of this structure: `[ header nonce || header ciphertext || Blake2b(header nonce || header ciphertext), aka the header hash || chunk 1 nonce || chunk 1 ciphertext || Blake2b(header hash || chunk 1 nonce || chunk 1 ciphertext) || ... || chunk N's nonce || chunk N's ciphertext || Blake2b(chunk N-1's hash || chunk N's nonce || chunk N's ciphertext || SHA512(key || everything previous) ]`.

That is, the trailing SHA512 HMAC is calculated as such: `SHA512(key || header nonce || header ciphertext || Blake2b(header nonce || header ciphertext) aka the header hash || chunk 1 nonce || chunk 1 ciphertext || Blake2b(header hash || chunk 1 nonce || chunk 1 ciphertext) || ... || chunk N's nonce || chunk N's ciphertext || Blake2b(chunk N-1's hash || chunk N's nonce || chunk N's ciphertext))


#### Why add a SHA512 hash to the end?  Isn't that redundant?

The trailing SHA512 hash accomplishes three things at once:

1. Marking the end of the entire miniLeap message (no an attacker can't truncate it by deleting the last 1 or more chunks),

2. Making it so both Blake2b and SHA512 need to be broken in order for an attacker to tamper with a miniLeap message without getting caught, and

3. Making it possible for decryptors to not have to decrypt _anything_ -- not even the header -- without first ensuring the integrity of the entire miniLeap message, which is important in some contexts.


#### Why add a Blake2b hash to the end of each chunk?  Isn't that redundant?

The rolling Blake2b hash at the end of each chunk accomplishes two things at once:

1. Cryptographically-connected chunks, thanks to the rolling!  The chunk-trailing hash isn't just a hash of that chunk's nonce and ciphertext -- indeed, this would be redundant, since we're using authenticated cryptography for each individual chunk -- but rather chunk N's Blake2b hash is calculated as such: `Blake2b(key || header nonce || header ciphertext || Blake2b(header nonce || header ciphertext) || chunk 1 nonce || chunk 1 ciphertext || Blake2b(chunk 1 nonce || chunk 1 ciphertext) || ... || chunk N's nonce || chunk N's ciphertext)`.

2. Making it so we can detect a tampered-with message (e.g., the attacker deleted the last chunk but kept everything else the same) _early_, without needing to either decrypt or hash all the chunks first.  This enables safe, efficient, truly streaming decryption.

Arguably what _is_ redundant is using authenticated cryptography for
each thunk, though this prevents the header from being tampered with
without detection even before a decryptor has checked the trailing
Blake2b hash -- a nice little bonus.  Plus, NaCl/libsodium is widely
available in various programming languages, making it a good choice to
place at the foundation of miniLeap.
