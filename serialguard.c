
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "monocypher.h"
#include "serialguard.h"
//     Information issue de la documentation de monocypher
// --- cypher
//
//     In-place encryption:
// uint8_t key  [32];    /* Random, secret session key  */
// uint8_t nonce[24];    /* Use only once per key       */
// uint8_t text [12] = "Lorem ipsum"; /* Secret message */
// uint8_t mac  [16];    /* Message authentication code */
// arc4random_buf(key,   32);
// arc4random_buf(nonce, 24);
// crypto_aead_lock(text, mac,
//                  key, nonce,
//                  NULL, 0,
//                  text, sizeof(text));
// /* Wipe secrets if they are no longer needed */
// crypto_wipe(key, 32);
// /* Transmit cipher_text, nonce, and mac over the network,
//  * store them in a file, etc.
//  */

// In-place decryption:

// uint8_t        key  [32]; /* Same as the above             */
// const uint8_t  nonce[24]; /* Same as the above             */
// const uint8_t  mac  [16]; /* Received from along with text */
// uint8_t        text [12]; /* Message to decrypt            */
// if (crypto_aead_unlock(text, mac, key, nonce,
//                        NULL, 0,
//                        text, sizeof(text))) {
// 	/* The message is corrupted.
// 	 * Wipe key if it is no longer needed,
// 	 * and abort the decryption.
// 	 */
// 	crypto_wipe(key, 32);
// } else {
// 	/* ...do something with the decrypted text here... */
// 	/* Finally, wipe secrets if they are no longer needed */
// 	crypto_wipe(text, 12);
// 	crypto_wipe(key, 32);
// }

// --- Hashing
//
// Hashing a message all at once:
// uint8_t hash   [64]; /* Output hash (64 bytes)          */
// uint8_t message[12] = "Lorem ipsum"; /* Message to hash */
// crypto_blake2b(hash, sizeof(hash), message, sizeof(message));

// --- Key exchanged
//
// Generate a pair of shared keys with your secret key and their public key
//  (this can help nonce management for full duplex communications).
// const uint8_t their_pk     [32]; /* Their public key          */
// uint8_t       your_sk      [32]; /* Your secret key           */
// uint8_t       your_pk      [32]; /* Your public key           */
// uint8_t       shared_secret[32]; /* Shared secret (NOT a key) */
// arc4random_buf(your_sk, 32);
// crypto_x25519_public_key(your_pk, your_sk);
// crypto_x25519(shared_secret, your_sk, their_pk);
// /* Wipe secrets if they are no longer needed */
// crypto_wipe(your_sk, 32);

// uint8_t shared_keys[64]; /* Two shared session keys */
// crypto_blake2b_ctx ctx;
// crypto_blake2b_init  (&ctx, 64);
// crypto_blake2b_update(&ctx, shared_secret, 32);
// crypto_blake2b_update(&ctx, your_pk      , 32);
// crypto_blake2b_update(&ctx, their_pk     , 32);
// crypto_blake2b_final (&ctx, shared_keys);
// const uint8_t *key_1 = shared_keys;      /* Shared key 1 */
// const uint8_t *key_2 = shared_keys + 32; /* Shared key 2 */
// /* Wipe secrets if they are no longer needed */
// crypto_wipe(shared_secret, 32);

// utilisation de la clef privé si elle est fournis (aucune raison de la faire générer plusieurs fois)
// PSK est aussi une entrée d'une donnnée communes (secret partagé)
// création de la clef si elle est vide
void sg_init(sg_t *sg,
             uint8_t static_priv_in[SG_KEY_LEN],
             uint8_t psk_in[SG_PSK_LEN])
{
    if (static_priv_in)
    { /* Clé statique déjà fournie   */
        memcpy(sg->static_priv, static_priv_in, SG_KEY_LEN);
    }
    else
    { /* Sinon on la génère          */
        sg_random(sg->static_priv, SG_KEY_LEN);
    }
    crypto_x25519_public_key(sg->static_pub, sg->static_priv);
    if (psk_in)
    {
        memcpy(sg->psk, psk_in, SG_PSK_LEN);
    }
    else
    {
        memset(sg->psk, 0, SG_PSK_LEN); /* PSK “nulle” */
    }
}

void sg_get_static_priv(sg_t *sg,  uint8_t static_priv_in[SG_KEY_LEN])
{
    memcpy(static_priv_in, sg->static_priv, SG_KEY_LEN);
}

void sg_session_init(sg_session_t *sg_session) {
    /* Génère l’éphémère */
    sg_random(sg_session->eph_priv, SG_KEY_LEN);
    crypto_x25519_public_key(sg_session->eph_pub, sg_session->eph_priv);
    sg_session->send_ctr = 0; // compteur 64 b (nonce TX)
    sg_session->recv_ctr = 0; // compteur 64 b (nonce RX)   
}

// Création d'un buffer à envoyer à Bob pour l'échange de clef
// Création d'une clef ephèmere asymétrique
// Création d'un  mélange de clef
int sg_handshake_make(sg_t *sg, sg_session_t *sg_session, uint8_t out[SG_MAX_FRAME])
{
    /* Message = static_pub ‖ eph_pub  (64 octets) */
    memcpy(out, sg->static_pub, SG_KEY_LEN);
    memcpy(out + SG_KEY_LEN, sg_session->eph_pub, SG_KEY_LEN);
    return 2*SG_KEY_LEN;
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}   

// hash de 4 buffers de 32 octets
static void blake_hash_4(
    uint8_t out[2*SG_KEY_LEN],
    const uint8_t a[SG_KEY_LEN],
    const uint8_t b[SG_KEY_LEN],
    const uint8_t c[SG_KEY_LEN],
    const uint8_t d[SG_KEY_LEN])
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 2*SG_KEY_LEN);
    crypto_blake2b_update(&ctx, a, SG_KEY_LEN);
    crypto_blake2b_update(&ctx, b, SG_KEY_LEN);
    crypto_blake2b_update(&ctx, c, SG_KEY_LEN);
    crypto_blake2b_update(&ctx, d, SG_KEY_LEN);
    crypto_blake2b_final(&ctx, out);
}

// Récéption d'un buffer à envoyer à Bob pour l'échange de clef et création de la clef de session symétrique
int sg_handshake_recv(sg_t *sg, sg_session_t *sg_session, const uint8_t *in, size_t in_len)
{
    if (in_len != 2*SG_KEY_LEN)
        return -1; /* format invalide           */

    const uint8_t *peer_static_pub = in;
    const uint8_t *peer_eph_pub = in + SG_KEY_LEN;

    /*---- 3 × DH :  S(E) ‖ E(S) ‖ E(E) --------------------------------*/
    uint8_t dh[3][SG_KEY_LEN];

    /* 1. S(E) : notre statique  ×  leur éphémère */
    crypto_x25519(dh[0], sg->static_priv, peer_eph_pub);
    printf("dh[0] S(E): ");
    for (size_t i = 0; i < SG_KEY_LEN; i++) {
        printf("%02x", dh[0][i]);
    }
    /* 2. E(S) : notre éphémère ×  leur statique  */
    crypto_x25519(dh[1], sg_session->eph_priv, peer_static_pub);
    printf("\ndh[1] E(S): ");
    for (size_t i = 0; i < SG_KEY_LEN; i++) {
        printf("%02x", dh[1][i]);
    }   
    /* 3. E(E) : notre éphémère ×  leur éphémère */
    crypto_x25519(dh[2], sg_session->eph_priv, peer_eph_pub);
    printf("\ndh[2] E(E): ");
    for (size_t i = 0; i < SG_KEY_LEN; i++) {
        printf("%02x", dh[2][i]);
    }
    printf("\n");
    /* 4. le PSK */

    /*---- HKDF ---------------------------------------------------------*/    
    uint8_t okm[64]; /* send_key | recv_key */

    // Le but du tri est d'avoir toujours le même ordre chez Alice et bob
    if(memcmp(dh[0], dh[1], SG_KEY_LEN) > 0) {
        blake_hash_4(okm, dh[0], dh[1], dh[2], sg->psk);    
    } else {
        blake_hash_4(okm, dh[1], dh[0], dh[2], sg->psk);
    }
    print_hex("okm ", okm, sizeof(okm));        

    /*---- Attribution des sens (TX/RX) ---------------------------------
     *  Convention : celui dont static_pub est « le plus petit » prend
     *  okm[0..31] en clé TX, l’autre en clé RX (et inversement).       */
    int we_are_low =
        memcmp(sg->static_pub, peer_static_pub, SG_KEY_LEN) < 0;

    if (we_are_low)
    {
        memcpy(sg_session->send_key, okm, SG_KEY_LEN);
        memcpy(sg_session->recv_key, okm + SG_KEY_LEN, SG_KEY_LEN);
    }
    else
    {
        memcpy(sg_session->send_key, okm + SG_KEY_LEN, SG_KEY_LEN);
        memcpy(sg_session->recv_key, okm, SG_KEY_LEN);
    }

    /* house-keeping */
    crypto_wipe(okm, sizeof(okm));
    crypto_wipe(dh, sizeof(dh));
    crypto_wipe(sg_session->eph_priv, SG_KEY_LEN); /* plus besoin */

    return 0;
}

// frame contient le chiffré + le MAC + le nonce
// len_io est la taille de frame (en entrée) et la taille de frame + MAC + nonce(en sortie)
void sg_encrypt(sg_session_t *sg_session, uint8_t *frame, size_t *len_io) 
{
    sg_session->send_ctr ++; // nonce unique par clef
    uint8_t nonce[SG_NONCE_LEN]={0};
    memcpy(nonce, &sg_session->send_ctr, sizeof(sg_session->send_ctr)); 

    crypto_aead_lock(frame, frame + *len_io,
                     sg_session->send_key, nonce,
                     NULL, 0,
                     frame, *len_io);

    *len_io += SG_MAC_LEN; 
    //memcpy(frame+*len_io, nonce, SG_NONCE_LEN); // ajout du nonce à la fin du buffer
    //*len_io += SG_NONCE_LEN; // ajout de la taille du nonce à la fin du buffer
}

// frame contient le chiffré + le MAC + le nonce
// len_io contient la taille du déchiffré en sortie et la taille du chiffré + MAC + nonce en entrée
int sg_decrypt(sg_session_t *sg_session, uint8_t *frame, size_t *len_io) {
    //size_t c_len = *len_io - SG_MAC_LEN - SG_NONCE_LEN;
    size_t c_len = *len_io - SG_MAC_LEN;
    
    int success = 0;
    for(int i =0; i<10; i++) {
        sg_session->recv_ctr++;
        uint8_t nonce[SG_NONCE_LEN]={0};
        memcpy(nonce, &sg_session->recv_ctr, sizeof(sg_session->recv_ctr)); 

        if (!crypto_aead_unlock(frame,
                           frame + c_len,
                           sg_session->recv_key, nonce,
                           NULL, 0,
                           frame, c_len)) {
            success = 1; // déchiffement réussi
            break;                              
        }
    }
    *len_io = c_len;
    return success;
}

// gestion d'un envoie de message avec seulement la clef publique du récepteur sans handshake
//  le but est de chiffrer le message avec la clef publique du récepteur, la clef publique est
//  envoyé avec le chiffré
//  l'event contient le nonce + la clef publique emeteur + le clef publique ephemere emeteur + le chiffré + le mac

/* pour gérer la crypto, le message d'origine grandi de 104 octets*/
#define SG_TRAILER_LEN (SG_NONCE_LEN + SG_MAC_LEN + 2 * SG_KEY_LEN) /* 104 */
#define SG_KDF_IN_LEN (2 * SG_KEY_LEN + SG_PSK_LEN)                 /* 96  */

/*=========================  Encrypt  =============================*/
size_t sg_encrypt_event(sg_t *sg,
                        uint8_t frame[static SG_MAX_FRAME],
                        size_t *frame_size,
                        const uint8_t peer_pub[SG_KEY_LEN])
{
    if (!sg || !frame || !frame_size || !peer_pub)
        return 0;
    size_t plain = *frame_size, total = plain + SG_TRAILER_LEN;
    if (total > SG_MAX_FRAME)
        return 0;

    /*--- 1) éphémère + S₁ ---------------------------------------*/
    uint8_t eph_priv[SG_KEY_LEN], eph_pub[SG_KEY_LEN];
    sg_random(eph_priv, SG_KEY_LEN);
    crypto_x25519_public_key(eph_pub, eph_priv);
    uint8_t S1[SG_KEY_LEN];
    crypto_x25519(S1, eph_priv, peer_pub); /* FS part   */
    crypto_wipe(eph_priv, SG_KEY_LEN);

    /*--- 2) statique + S₂ ---------------------------------------*/
    uint8_t S2[SG_KEY_LEN];
    crypto_x25519(S2, sg->static_priv, peer_pub); /* Auth part */

    /*--- 3) KDF --------------------------------------------------*/
    uint8_t kdf_in[SG_KDF_IN_LEN];
    memcpy(kdf_in, S1, SG_KEY_LEN);
    memcpy(kdf_in + SG_KEY_LEN, S2, SG_KEY_LEN);
    memcpy(kdf_in + 2 * SG_KEY_LEN, sg->psk, SG_PSK_LEN);
    uint8_t key[SG_KEY_LEN];
    crypto_blake2b(key, sizeof key, kdf_in, sizeof kdf_in);
    crypto_wipe(kdf_in, sizeof kdf_in);
    crypto_wipe(S1, SG_KEY_LEN);
    crypto_wipe(S2, SG_KEY_LEN);

    /*--- 4) nonce + AEAD ----------------------------------------*/
    uint8_t nonce[SG_NONCE_LEN];
    sg_random(nonce, SG_NONCE_LEN);
    uint8_t mac[SG_MAC_LEN];
    crypto_aead_lock(frame, mac, key, nonce, NULL, 0, frame, plain);
    crypto_wipe(key, SG_KEY_LEN);

    /*--- 5) suffixe ---------------------------------------------*/
    uint8_t *c = frame + plain;
    memcpy(c, nonce, SG_NONCE_LEN);
    c += SG_NONCE_LEN;
    memcpy(c, mac, SG_MAC_LEN);
    c += SG_MAC_LEN;
    memcpy(c, eph_pub, SG_KEY_LEN);
    c += SG_KEY_LEN;
    memcpy(c, sg->static_pub, SG_KEY_LEN);
    c += SG_KEY_LEN;

    *frame_size = total;
    return total;
}

/*=========================  Decrypt  =============================*/
size_t sg_decrypt_event(sg_t *sg,
                        uint8_t frame[static SG_MAX_FRAME],
                        size_t *frame_size)
{
    if (!sg || !frame || !frame_size)
        return 0;
    size_t total = *frame_size;
    if (total < SG_TRAILER_LEN || total > SG_MAX_FRAME)
        return 0;

    /* découpe */
    size_t cipher_len = total - SG_TRAILER_LEN;
    uint8_t *nonce = frame + cipher_len;
    uint8_t *mac = nonce + SG_NONCE_LEN;
    uint8_t *eph_pub = mac + SG_MAC_LEN;
    uint8_t *sender_pub = eph_pub + SG_KEY_LEN;

    /*--- 1) S₁ & S₂ ---------------------------------------------*/
    uint8_t S1[SG_KEY_LEN], S2[SG_KEY_LEN];
    crypto_x25519(S1, sg->static_priv, eph_pub);    /* FS part   */
    crypto_x25519(S2, sg->static_priv, sender_pub); /* Auth part */

    uint8_t kdf_in[SG_KDF_IN_LEN];
    memcpy(kdf_in, S1, SG_KEY_LEN);
    memcpy(kdf_in + SG_KEY_LEN, S2, SG_KEY_LEN);
    memcpy(kdf_in + 2 * SG_KEY_LEN, sg->psk, SG_PSK_LEN);
    uint8_t key[SG_KEY_LEN];
    crypto_blake2b(key, sizeof key, kdf_in, sizeof kdf_in);
    crypto_wipe(kdf_in, sizeof kdf_in);
    crypto_wipe(S1, SG_KEY_LEN);
    crypto_wipe(S2, SG_KEY_LEN);

    /*--- 2) AEAD unlock -----------------------------------------*/
    int err = crypto_aead_unlock(frame, mac, key, nonce,
                                 NULL, 0, frame, cipher_len);
    crypto_wipe(key, SG_KEY_LEN);
    if (err)
        return 0; /* MAC invalide */

    *frame_size = cipher_len;
    return cipher_len;
}
