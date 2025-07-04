# SERIALGUARD #

Cryptographic library for embedded communication

Serialguard is a cryptographic library that uses recommended primitives to provide simple, embedded, offline—but secure—communication, without requiring the user to understand the underlying algorithms.

## How to install?

Copy the C files into your project and use them, in the same way as Monocypher.

## Example

 gcc -o sg monocypher.c serialguard.c serialguard_test.c && ./sg

## Usage

User code must supply a cryptographically secure random‑number generator. None is provided, because the implementation depends on the target hardware and operating system.

Protocol framing is not handled; this library works at the packet level. It is up to the user to provide complete packets.

If the peers become desynchronised—for instance after repeated transmission errors—the user must perform a new handshake on both sides to resynchronise the sessions. It is also advisable to redo the handshake periodically to rotate the session key (e.g. every 2 h or once a day, depending on throughput).

The system maintains a counter to prevent replay attacks, and each packet includes a Message Authentication Code (MAC).

## Key management

The main challenge is ensuring you are talking to the intended peer. We assume the private key remains secret, but that alone is not sufficient.

Private keys must stay on the device and must never be transmitted. If compromised, they need to be replaced or revoked. The library offers utilities to regenerate easly both session keys and static keys.

### Static keys

Static keys are generated once per device and must be stored internally (e.g. in flash).

The system on the other side can verify that the key remains the same for a given device (TOFU — trust on first use). This mechanism is intentionally left out of Serialguard to keep integration simple and because, in certain scenarios, devices are not directly reachable via the Internet (e.g. a basement radio module) to make the key signed by a trusted entity.

### The PSK

A second option is a shared key (PSK) consisting of 32 random bytes. The PSK can be hard‑coded (with the deployment issues that implies), injected at manufacture time into eFuses, or set during device installation (which is cumbersome). Combining these methods is also possible. The aim is to minimise information leakage.

If you mix PSK generation techniques, each component must have enough entropy (≥ 64 bits) to resist brute‑force attacks. For example, you can XOR a 32‑byte eFuse constant with a 32‑byte code constant or hash both with BLAKE2b.

### key signatures & PKI

During installation, the public key can be signed by a central authority (CA). The device distributes the signed key along with its signature, so a third party can verify it if they possess the CA’s public key.

Updating this key is the difficult part. The library provides no direct support for such a scheme, as it would require mandatory communication with the central system and deployment of a global key.

## API ##

### cryptographic random source

A function with the following signature must be provided :

 void sg_random(uint8_t *dst, size_t len);

### Initialisation

This function creates the sg object. If the key fields are empty, new keys are generated. They should then be saved to flash.

 void sg_init(sg_t *sg, uint8_t static_priv[SG_KEY_LEN], uint8_t psk[SG_PSK_LEN]);

### Private‑key access

 void sg_get_static_priv(sg_t *sg, uint8_t static_priv_in[SG_KEY_LEN]);

### Handshake

These two functions establish the cryptographic session (note the larger buffer sizes after the call) :

 int sg_handshake_make(sg_t *sg, sg_session_t *sg_session, uint8_t out[SG_MAX_FRAME]);
 int sg_handshake_recv(sg_t *sg, sg_session_t *sg_session, const uint8_t *in, size_t in_len);

### In‑place encryption/decryption

 int sg_encrypt(sg_session_t *sess, uint8_t *frame, size_t *len_io);
 int sg_decrypt(sg_session_t *sess, uint8_t *frame, size_t *len_io);

### One‑shot messages

These helper functions are useful for sending a single message when only the receiver’s public key is known. They add an overhead of 100 bytes.

 size_t sg_decrypt_event(sg_t *sg,
    uint8_t frame[static SG_MAX_FRAME],
    size_t *frame_size);
 size_t sg_encrypt_event(sg_t *sg,
    uint8_t frame[static SG_MAX_FRAME],
    size_t *frame_size,
    const uint8_t peer_pub[SG_KEY_LEN]);

## Cryptographic scheme

Bidirectional communication

* Static key — long‑term sender identity
* Ephemeral key — handshake
* Session key — derived from the above plus the PSK

Events / messages

* Static key — long‑term sender identity
* Ephemeral key — generated and sent with the message
* Session key — derived from the above plus the PSK

## Security considerations

Serialguard reduces integration pitfalls, but it is not a complete security solution. Keep the following in mind:

* Strong randomness is mandatory. Ensure your sg_random() implementation passes statistical tests and cannot be predicted or forced into a low‑entropy state.
* Protect secret keys. Store static private keys in non‑volatile memory that is read‑protected (e.g. eFuses, locked flash pages) and erase sensitive buffers from RAM after use.
* Update and audit. Track upstream releases, apply patches promptly, and have an independent security audit before production deployment.
* Model your threat. Adjust handshake frequency, PSK security, and out‑of‑band verification to the risks of your specific environment.

## Error‑handling guidelines

Functions returns size or boolean of success (0 == false/failure, 1 == true/success)