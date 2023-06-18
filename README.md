# miniLeap

miniLeap is a command line tool, encryption library, and simple
streaming encryption scheme built on NaCl/libsodium's SecretBox but
without the complexity of libsodium 1.0.14+'s secretstream.


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

`[ header (see below) ]` and `[ 1+ chunks of size Chunk Size specified in the header ]`

The final chunk may be below the stated Chunk Size.

The 5-byte **header** (before encryption):

`[ 3 bytes: Chunk Size (uint24, big endian) || 2 bytes: message type (uint16, big endian) (see next section) ]`

Min permitted Chunk Size: 1,024 bytes.

Consider choosing <= 64KB chunks if you need random access (to
download/decrypt less data) or if you need to send data in real-time
(e.g., voice calls).

Consider using 1MB+ chunks if you don't need either of the above (in
order to perform fewer encryptions/decryptions).

The last chunk may be smaller than the given chunk size, but the
others may not be (except the header, obviously, which is small and of
fixed size).

Max Chunk Size: 2**24 - 1 bytes == 16,777,215 == ~16MB

Total possible valid miniLeap message types: 2**16 - 1 == 65,535


###### Ciphertext Structure

Once you have encrypted a piece of data (e.g., text or a file), the
resulting miniLeap message will have the following structure:

`[ 109-byte header: 24-byte nonce + 5-byte encrypted body + 16-byte libsodium overhead + 64-byte Blake2b hash ]`

followed by 1 or more data chunks that each encrypt N bytes, where N
is equal to the header-provided Chunk Size for every chunk except
(perhaps) the last one, which may be of size less than N:

`[ N+105-byte chunk: 24-byte nonce + 1-byte last chunk indicator + N-byte encrypted body + 16-byte libsodium overhead + 64-byte Blake2b rolling hash ]`

The last chunk indicator byte should be 0 if the chunk is not the last
byte, and a 1 if it is.


#### Message Types

0: Invalid type; sanity check

1: UTF-8 encoded text (e.g., chat message)

2: URL, including the protocol (e.g., https://leapchat.org, not just leapchat.org)

3: A command

4: Passphrase (first and only non-header chunk is 256 bytes: 1 uint8 to tell us the passphrase length L (must be at least 75), then L bytes of passphrase, then `255 - L` random bytes of padding)

5: File (first non-header chunk is 256 bytes before encryption: 1 uint8 to tell us the filename length L, then L bytes, then `255 - L` bytes of random byte padding; remaining chunks use the scheme described above, namely 1+ chunks of nonce-prefixed ciphertext)

6: File with file path, not just filename + body (details TBD)

7 through 65,535: Reserved for future assignment. Please submit a PR to propose a new message type.


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

In general, the overhead of encrypting data with miniLeap is 109 bytes
(for the header 24-byte header + 5-byte body + 64-byte Blake2b hash;
see below) + 105 bytes/chunk (for each chunk's 24-byte nonce + 1 byte
last chunk indicator byte prepended to the body + 16-byte overhead from
libsodium's SecretBox encryption + 64-byte Blake2b rolling hash).

If you're encrypting 1,000,000 bytes, all in one chunk, the resulting
ciphertext is thus 1,000,214 bytes (0.0214% overhead).

If you're encrypting 100 bytes, all in one chunk, the resulting
ciphertext is 314 bytes (214% overhead).

If you're encrypting just 1 byte, the resulting ciphertext is 215
bytes (21,400% overhead, which sounds like a lot, but in absolute
terms that's just 214 bytes of overhead -- well worth the price of a
simple spec and thus a simple implementation in many programming
languages):

`[ header (109 bytes) || chunk 1 (106 total bytes: 1 byte of content and 105 bytes of overhead) ]`

header: `[ 24-byte nonce || 5-byte body + 16-byte authentication tag || 64-byte Blake2b MAC ]`

chunk 1: `[ 24-byte nonce || 1-byte last chunk indicator + 1-byte body + 16-byte authentication tag || 64-byte rolling Blake2b MAC ]`

The end result of all this encrypting and hashing is a file of this structure:

`[ header nonce || header ciphertext || Blake2b(key || header nonce || header ciphertext) || chunk 1 nonce || chunk 1 ciphertext || Blake2b(the header's Blake2b hash || chunk 1 nonce || chunk 1 ciphertext) || ... || chunk N's nonce || chunk N's ciphertext || Blake2b(chunk N-1's Blake2b hash || chunk N's nonce || chunk N's ciphertext) ]`.


#### Why add a Blake2b hash to the end of each chunk?  Isn't that redundant since each chunk is encrypted using libsodium's SecretBox?

The rolling Blake2b hash at the end of each chunk accomplishes two things at once:

1. Cryptographically-connected chunks, thanks to the rolling!  The chunk-trailing hash isn't just a hash of that chunk's nonce and ciphertext -- indeed, this would be redundant, since we're using authenticated cryptography for each individual chunk -- but rather chunk N's Blake2b hash is calculated as such: `Blake2b(key || header nonce || header ciphertext || Blake2b(header nonce || header ciphertext) || chunk 1 nonce || chunk 1 ciphertext || Blake2b(chunk 1 nonce || chunk 1 ciphertext) || ... || chunk N's nonce || chunk N's ciphertext)`.

2. Making it so we can detect a tampered-with message (e.g., the attacker deleted the last chunk but kept everything else the same) _early_, without needing to either decrypt or hash all the chunks first.  This enables safe, efficient, truly streaming decryption.

Arguably what _is_ redundant is using authenticated cryptography for
each chunk, though this prevents a chunk from being tampered with
without detection even before a decryptor has checked its trailing
Blake2b hash -- a nice little bonus.  Plus, NaCl/libsodium is widely
available in various programming languages, making it an excellent
choice to place at the foundation of miniLeap.


#### Why is the chunk size 100,000 bytes?

Because of the following benchmarks and related metrics from
encrypting and decrypting a 15GB file:

(Winners and might-a-well-be-ties are bolded --)

---

**Encrypting** and writing the result to disk:

| Chunk size | Time          |
|       ---: | :---          |
| 1,000,000  |   2m51.776s   |
|   100,000  | **1m54.216s** |
|    65,000  | **1m48.053s** |
|    10,000  | **1m47.861s** |

---

**Decrypting** and writing the result to disk:

| Chunk size | Time          |
|       ---: | :---          |
| 1,000,000  |   2m38.011s   |
|   100,000  | **1m37.533s** |
|    65,000  | **1m38.739s** |
|    10,000  |   2m3.418s    |

---

**Overhead**.  That is, the encrypted file size (when encrypted with
the given chunk size) minus the original file size, divided by the
original file size (~15GB):

| Chunk size | Total overhead | Percentage overhead |
|       ---: |           ---: | :---                |
| 1,000,000  | **1,657,324**  | **0.0105%**         |
|   100,000  |  16,571,944    |   0.105%            |
|    65,000  |  25,495,264    |   0.16154%          |
|    10,000  | 165,718,039    |   1.05%             |

---

The original rationale for allowing very small chunk sizes (i.e., <=
10kb) was to support real-time use cases (e.g., voice calls).  In
those situations, users should just use plain secretbox.
