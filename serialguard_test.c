#include "serialguard.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h> // close()
#include <stdbool.h>
// ------------------------------------------------------------------
// <<<  Petits « glue » manquants entre notre code et Monocypher  >>>
// ------------------------------------------------------------------
// 1. sg_random() n'est PAS fourni par Monocypher : on se rabat sur
// /dev/urandom (Unix) pour cette démo. En firmware, remplace par ton TRNG.
 void sg_random(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("/dev/urandom"); exit(1); }
    ssize_t r = read(fd, buf, len);
    if (r < (ssize_t)len) { perror("read urandom"); exit(1); }
    close(fd);
}


void print_sg(const char *label, sg_t *sg) {
    printf("%s: \n static_priv ", label);
    for (size_t i = 0; i < SG_KEY_LEN; i++) {
        printf("%02x", sg->static_priv[i]);
    }
    printf("\n static_pub  ");
    for (size_t i = 0; i < SG_KEY_LEN; i++) {
        printf("%02x", sg->static_pub[i]);
    }
    printf("\n psk         ");
    for (size_t i = 0; i < SG_PSK_LEN; i++) {
        printf("%02x", sg->psk[i]);
    }
    printf("\n");
}

void print_sg_session(const char *label, sg_session_t *sg_session) {
    printf("%s: \n eph_priv ", label);
    for (size_t i = 0; i < SG_KEY_LEN; i++) {
        printf("%02x", sg_session->eph_priv[i]);
    }
    printf("\n eph_pub ");
    for (size_t i = 0; i < SG_KEY_LEN; i++) {
        printf("%02x", sg_session->eph_pub[i]);
    }
    printf("\n send_key ");
    for (size_t i = 0; i < SG_KEY_LEN; i++) {
        printf("%02x", sg_session->send_key[i]);
    }
    printf("\n recv_key ");
    for (size_t i = 0; i < SG_KEY_LEN; i++) {
        printf("%02x", sg_session->recv_key[i]);
    }
    printf("\n");
    printf(" send_ctr: %llu\n", sg_session->send_ctr);
    printf(" recv_ctr: %llu\n", sg_session->recv_ctr);
}   

int test1() {
    sg_t alice_sg = {0};
    sg_t bob_sg = {0};
    sg_session_t alice_sg_session = {0};
    sg_session_t bob_sg_session = {0};

    uint8_t A2B[SG_MAX_FRAME] = {0}; int A2B_len = 0;
    uint8_t B2A[SG_MAX_FRAME] = {0}; int B2A_len = 0;
    
    // Initialize the SerialGuard instance
    sg_init(&alice_sg, NULL, NULL);
    sg_init(&bob_sg, NULL, NULL);
    
    print_sg("Alice SerialGuard", &alice_sg);
    print_sg("Bob SerialGuard", &bob_sg);   
    
    sg_session_init(&alice_sg_session);
    sg_session_init(&bob_sg_session);     

    // Perform handshake
    A2B_len = sg_handshake_make(&alice_sg, &alice_sg_session, A2B);
    if (A2B_len < 0) {
        printf("Handshake_make A failed\n");
        return -1;
    }

    B2A_len= sg_handshake_make(&bob_sg, &bob_sg_session, B2A);
    if (B2A_len < 0) {
        printf("Handshake_make B failed\n");
        return -1;
    }

    print_sg("Alice SerialGuard", &alice_sg);
    print_sg_session("Alice Session", &alice_sg_session);
    print_sg("Bob SerialGuard", &bob_sg);   
    print_sg_session("Bob Session", &bob_sg_session);
    
    // Receive the handshake
    int recv_result = sg_handshake_recv(&alice_sg, &alice_sg_session, B2A, B2A_len);
    if (recv_result < 0) {
        printf("Handshake A reception failed\n");
        return -1;
    }
    
    recv_result = sg_handshake_recv(&bob_sg, &bob_sg_session, A2B, A2B_len);
    if (recv_result < 0) {
        printf("Handshake B reception failed\n");
        return -1;
    }

    printf("\n\n --- Handshake successful\n");
    
    print_sg("Alice SerialGuard", &alice_sg);
    print_sg_session("Alice Session", &alice_sg_session);
    print_sg("Bob SerialGuard", &bob_sg);   
    print_sg_session("Bob Session", &bob_sg_session);
    
    // --- Encrypt and decrypt a message from Alice to Bob

    uint8_t message[] = "Hello, SerialGuard!";
    size_t message_len = sizeof(message); 
    print_hex("Original message ", message, message_len); 
    memcpy(A2B, message, message_len);
    sg_encrypt(&alice_sg_session, A2B, &message_len); // le message chiffré est plus long que le message d'origine

    print_hex("Encrypted message", A2B, message_len); // Affiche le message chiffré
    print_hex("MAC", A2B + message_len - SG_MAC_LEN - SG_NONCE_LEN, SG_MAC_LEN);
    print_hex("NONCE", A2B + message_len - SG_NONCE_LEN, SG_NONCE_LEN);
    int ret = sg_decrypt(&bob_sg_session, A2B, &message_len); // le message déchiffré est plus court que le message d'origine
    if(ret < 0) {
        printf("Decryption failed\n");
    }
    print_hex("Decrypted message", A2B, message_len); // Affiche le message déchiffré   
    printf("%s vs %s\n ", message,A2B);

    print_sg("Alice SerialGuard", &alice_sg);
    print_sg_session("Alice Session", &alice_sg_session);
    print_sg("Bob SerialGuard", &bob_sg);   
    print_sg_session("Bob Session", &bob_sg_session);
    
    return !strcmp((char *)message, (char *)A2B);
}

// ordre différent pour le test 2
int test2() {
    sg_t alice_sg = {0};
    sg_session_t alice_sg_session = {0};
    
    sg_t bob_sg = {0};
    sg_session_t bob_sg_session = {0};
    
    uint8_t A2B[SG_MAX_FRAME] = {0}; int A2B_len = 0;
    uint8_t B2A[SG_MAX_FRAME] = {0}; int B2A_len = 0;
    
    // Initialize the SerialGuard instance
    sg_init(&alice_sg, NULL, NULL);
    sg_session_init(&alice_sg_session);
    // Perform handshake
    A2B_len = sg_handshake_make(&alice_sg, &alice_sg_session, A2B);
    if (A2B_len < 0) {
        printf("Handshake_make A failed\n");
        return -1;
    }
   
    sg_init(&bob_sg, NULL, NULL);   
    sg_session_init(&bob_sg_session);     
    B2A_len= sg_handshake_make(&bob_sg, &bob_sg_session, B2A);
    if (B2A_len < 0) {
        printf("Handshake_make B failed\n");
        return -1;
    }
    int recv_result = sg_handshake_recv(&bob_sg, &bob_sg_session, A2B, A2B_len);
    if (recv_result < 0) {
        printf("Handshake B reception failed\n");
        return -1;
    }


    // Receive the handshake
    recv_result = sg_handshake_recv(&alice_sg, &alice_sg_session, B2A, B2A_len);
    if (recv_result < 0) {
        printf("Handshake A reception failed\n");
        return -1;
    }
    
    printf("\n\n --- Handshake successful\n");
   
    
    // --- Encrypt and decrypt a message from Alice to Bob

    uint8_t message[] = "Hello, SerialGuard!";
    size_t message_len = sizeof(message); 
    print_hex("Original message ", message, message_len); 
    memcpy(A2B, message, message_len);
    sg_encrypt(&alice_sg_session, A2B, &message_len); // le message chiffré est plus long que le message d'origine

    print_hex("Encrypted message", A2B, message_len); // Affiche le message chiffré
    print_hex("MAC", A2B + message_len - SG_MAC_LEN - SG_NONCE_LEN, SG_MAC_LEN);
    print_hex("NONCE", A2B + message_len - SG_NONCE_LEN, SG_NONCE_LEN);
    int ret = sg_decrypt(&bob_sg_session, A2B, &message_len); // le message déchiffré est plus court que le message d'origine
    if(ret < 0) {
        printf("Decryption failed\n");
    }
    print_hex("Decrypted message", A2B, message_len); // Affiche le message déchiffré   
    printf("%s vs %s\n ", message,A2B);

    print_sg("Alice SerialGuard", &alice_sg);
    print_sg_session("Alice Session", &alice_sg_session);
    print_sg("Bob SerialGuard", &bob_sg);   
    print_sg_session("Bob Session", &bob_sg_session);
    

    return !strcmp((char *)message, (char *)A2B);        
}

// test de retransmission de message
// supporte 10 pertes de message, et pas 11
int test_retransmit(int limit) {
    sg_t alice_sg = {0};
    sg_session_t alice_sg_session = {0};
    
    sg_t bob_sg = {0};
    sg_session_t bob_sg_session = {0};
    
    uint8_t A2B[SG_MAX_FRAME] = {0}; int A2B_len = 0;
    uint8_t B2A[SG_MAX_FRAME] = {0}; int B2A_len = 0;
    
    // Initialize the SerialGuard instance
    sg_init(&alice_sg, NULL, NULL);
    sg_session_init(&alice_sg_session);
    // Perform handshake
    A2B_len = sg_handshake_make(&alice_sg, &alice_sg_session, A2B);
    if (A2B_len < 0) {
        printf("Handshake_make A failed\n");
        return -1;
    }
   
    sg_init(&bob_sg, NULL, NULL);   
    sg_session_init(&bob_sg_session);     
    B2A_len= sg_handshake_make(&bob_sg, &bob_sg_session, B2A);
    if (B2A_len < 0) {
        printf("Handshake_make B failed\n");
        return -1;
    }
    int recv_result = sg_handshake_recv(&bob_sg, &bob_sg_session, A2B, A2B_len);
    if (recv_result < 0) {
        printf("Handshake B reception failed\n");
        return -1;
    }

    // Receive the handshake
    recv_result = sg_handshake_recv(&alice_sg, &alice_sg_session, B2A, B2A_len);
    if (recv_result < 0) {
        printf("Handshake A reception failed\n");
        return -1;
    }
    
    printf("\n\n --- Handshake successful\n");
    
    // --- Encrypt and decrypt a message from Alice to Bob

    uint8_t message[] = "Hello, SerialGuard!";
    size_t message_len = sizeof(message); 
    for(int i = 0; i < limit; i++) {
     
        memcpy(A2B, message, message_len);
        sg_encrypt(&alice_sg_session, A2B, &message_len); // simulation de perte de message
    }
    print_hex("Encrypted message", A2B, message_len); // Affiche le message chiffré
    print_hex("MAC", A2B + message_len - SG_MAC_LEN - SG_NONCE_LEN, SG_MAC_LEN);
    print_hex("NONCE", A2B + message_len - SG_NONCE_LEN, SG_NONCE_LEN);
    int ret = sg_decrypt(&bob_sg_session, A2B, &message_len); // le message déchiffré est plus court que le message d'origine
    if(ret < 0) {
        printf("Decryption failed\n");
    }
    print_hex("Decrypted message", A2B, message_len); // Affiche le message déchiffré   
    printf("%s vs %s\n ", message,A2B);

    print_sg("Alice SerialGuard", &alice_sg);
    print_sg_session("Alice Session", &alice_sg_session);
    print_sg("Bob SerialGuard", &bob_sg);   
    print_sg_session("Bob Session", &bob_sg_session);
    

    return !strcmp((char *)message, (char *)A2B);        
}


static bool round_trip(sg_t *sender, sg_t *receiver)
{
    uint8_t frame[SG_MAX_FRAME];
    uint8_t original[512];
    const size_t msg_len = 20;
   
    /* prépare un payload aléatoire */
    sg_random(original, msg_len);
    print_hex("Original message ", original, msg_len);  
    memcpy(frame, original, msg_len);
    size_t len = msg_len;

    /* chiffrement */
    size_t total = sg_encrypt_event(sender, frame, &len,
                                    receiver->static_pub);
    if (total == 0) return false;                     /* échec encrypt */
    print_hex("Encrypted message", frame, total); // Affiche le message chiffré 

    /* déchiffrement */
    size_t plain = sg_decrypt_event(receiver, frame, &total);
    if (plain != msg_len) return false;               /* échec decrypt */
    print_hex("Decrypted message", frame, plain); // Affiche le message déchiffré
    /* vérification */
    return memcmp(frame, original, msg_len) == 0;
}

/* ----------------------------------------------------------------- */
/*  Fonction publique d’auto-test                                    */
bool sg_message_selftest(void)
{
    uint8_t psk[SG_PSK_LEN] = "12345678901234567890123456789012"; /* 32 octets */

    sg_t alice = {0}, bob = {0};
    sg_init(&alice, NULL, psk);
    sg_init(&bob, NULL, psk);

    if (!round_trip(&alice, &bob)) return false;  /* Alice → Bob */
    if (!round_trip(&bob, &alice)) return false;  /* Bob   → Alice */

    return true;                                  /* tous OK */
}


int main() {
    int ret1 = test1();
    int ret2 = test2();
    int ret3 = test_retransmit(10);
    int ret4 = test_retransmit(11);
    int ret5 = sg_message_selftest();
    if(ret1) {
        printf("Test 1 passed ✓\n");
    } else {
        printf("Test 1 failed ❌\n");    
    }
    if(ret2) {
        printf("Test 2 passed ✓\n");
    } else {
        printf("Test 2 failed ❌\n");    
    }   
    if(ret3) {
        printf("Test retransmit (10) passed ✓\n");
    } else {
        printf("Test retransmit (10) failed ❌\n");    
    }   
    if(ret4) {
        printf("Test retransmit (11) failed ❌\n");
    } else {
        printf("Test retransmit (11) passed ✓\n");    
    }   
    if(ret5) {
        printf("Selftest message passed ✓\n");
    } else {
        printf("Selftest message failed ❌\n");    
    }
    return 0;
}   