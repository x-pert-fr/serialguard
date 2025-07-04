#pragma once
/*======================================================================
 *  SerialGuard – API publique (header)                                *
 *  Minimal secure channel au-dessus d’un lien série (UART, CAN, …)    *
 *  © 2024 – libre, sans garantie.                                     *
 *====================================================================*/

#include <stdint.h>
#include <stddef.h>

#define SG_KEY_LEN 32     /* X25519 / ChaCha key length */
#define SG_PSK_LEN 32     /* Pre-Shared-Key              */
#define SG_MAC_LEN 16     /* Poly1305 auth-tag           */
#define SG_NONCE_LEN 24   /* XChaCha20-Poly1305 nonce    */
#define SG_MAX_FRAME 1024 /* Max payload (+ MAC +... )   */

typedef struct
{
    uint8_t static_priv[SG_KEY_LEN]; // clef privé
    uint8_t static_pub[SG_KEY_LEN];  // la partie publique de la clef
    uint8_t psk[SG_PSK_LEN];         //  Nombre aléatoire commun à tous les noeuds de la communications (secret partagé) (XOR si on mélange 2 sources pour le générer)
} sg_t;

/* État d’une session chiffrée « SerialGuard »                    */
typedef struct
{
    uint8_t eph_pub[SG_KEY_LEN];
    uint8_t eph_priv[SG_KEY_LEN];
    uint8_t send_key[SG_KEY_LEN];
    uint8_t recv_key[SG_KEY_LEN];
    uint64_t send_ctr; /* compteur 64 b (nonce TX)  */
    uint64_t recv_ctr; /* compteur 64 b (nonce RX)  */
} sg_session_t;

/*  sg_random() – **à fournir** : TRNG, RNG matériel, etc.            */
void sg_random(uint8_t *dst, size_t len);

/*  sg_init()                                                         *
 *  – Si `static_priv` == NULL  ➜ génère une nouvelle paire statique. *
/* Cette chaine doit être sauvé en flash et n'a pas de raison d'être changé dans la vie du produit*/
/* psk est la chaine aléatoire partagé avec tous les noeuds */
void sg_init(sg_t *sg, uint8_t static_priv[SG_KEY_LEN], uint8_t psk[SG_PSK_LEN]);
void sg_get_static_priv(sg_t *sg,  uint8_t static_priv_in[SG_KEY_LEN]);

void sg_session_init(sg_session_t *sg_session);
/*  Handshake (2 messages de 32 octets)                               */
int sg_handshake_make(sg_t *sg, sg_session_t *sg_session, uint8_t out[SG_MAX_FRAME]);
int sg_handshake_recv(sg_t *sg, sg_session_t *sg_session, const uint8_t *in, size_t in_len);

    /*  Chiffrement / déchiffrement in-place                             */
void sg_encrypt(sg_session_t *sess, uint8_t *frame, size_t *len_io);
int sg_decrypt(sg_session_t *sess, uint8_t *frame, size_t *len_io);

void print_hex(const char *label, const uint8_t *data, size_t len);

/* chiffrement de message */
/* peer_pub est la clef publique du destinataire */
size_t sg_decrypt_event(sg_t *sg,
    uint8_t frame[static SG_MAX_FRAME],
    size_t *frame_size);
size_t sg_encrypt_event(sg_t *sg, 
    uint8_t frame[static SG_MAX_FRAME],
    size_t *frame_size,
    const uint8_t peer_pub[SG_KEY_LEN]);