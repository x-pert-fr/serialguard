# SERIALGUARD #

Cryptographic library for embedded communication

Serialguard est une librairy de crypto utilisant les primitives récommandées dans un but d'usage simple, embarqué, hors ligne, mais sécurisé, sans nécessiter de comprendre les algorithmes utilisés.

## Comment l'installer ? ##

* Copier les fichiers C dans son projet et l'utiliser. A la manière de monocypher.

## Exemple ##

 gcc -o sg monocypher.c serialguard.c serialguard_test.c && ./sg

## Utilisation ##

Le code utilisateur doit fournir une fonction de random de qualité cryptographique pour fonctionner. Elle n'est pas fournis, car elle dépend du hardware et du système utilisé.

Le "framing" du protocole n'est pas proposé. Cette library gére des paquets. C'est à l'utilisateur de lui fournir les paquets entiers.

En cas de désynchronisation, par exemple en cas d'erreur de transmission répété, c'est à l'utilisateur de refaire un handshake de chaque coté pour resynchroniser les sessions. Il est aussi souhaitable de refaire un handshake de temps en temps pour changer la clef de session (2h, 1 jour, selon le débit).

Le système contient un compteur pour éviter les rejeux. Les paquets contiennent aussi une validation du paquet (MAC).

## Gestion des clefs  ##

Le problème de la gestion des clef est d'être sûr que l'on parle à la bonne personne (machine). On part du principe que la clef privé reste secrète mais cela n'est pas suffisant.

Les clefs privés doivent rester secrète et ne doivent jamais circuler. En cas de compromission, il faut pouvoir les modifier ou les bannir. La lib fournis de quoi regénérer facilement les clefs de session et statiques.

### Les clefs statiques ###
Les clefs statiques sont générés une fois par le device et doivent être stoqué en interne dans la flash. Le système, "en face", peut vérifier que la clef est toujours identique pour le même device (TOFU, trust on first use). Ce n'est pas géré par la serialguard pour faciliter l'emploi et que dans certain cas d'usage, les boitiers ne sont pas directement joignable par internet (boitier radio en sous-sol).

### La PSK ###

Le deuxième moyen est l'utilisation d'une clef partagé (PSK) qui consiste en 32 octets aléatoire. Cette PSK peut être mise en dur dans le code, avec le problème de diffusion du code que cela implique, ou rajouté à la fabrication dans des efuse. Ou encore, elle peut être rajouté à l'installation du device (mais c'est lourd). Ou tout cela à la fois. Le but est d'éviter la fuite d'informations.

En cas de mélange de technique de génération de la PSK, pour être efficace chaque morceau doit avoir assez d'enthropie (64 bits minimum) pour éviter le brut force. Cela peut être une constante stoqué dans les efuse et une constante du code de chacune 32 octets qui sont XORé bit à bit ou qui passent dans la fonction de hash blake2b.

### Out of band ###

Pour renforcer encore la sécurité, il faut sortir la clef publique de device par un cannal différent du canal chiffré ("OUT of BAND"). Un système centrale peut ainsi associer clef et numéro de device de façon encore plus sécurisé. On évite les attaques "Man in the middle".

### Signature de clef, PKI ###

A l'installation du device, la clef publique peut être signé par un système central (CA). La clef signé est distribué avec la signature par le device, ainsi un 3 ième device peut vérifier cette signature si il dispose de la clef publique du système central.

La difficulté concernent la mise à jour de cette clef. IL n'y a pas de support pour ce schéma dans la lib, qui serait assez lourd (communication obligatoire avec un système central, déploiement d'une clef globale)

## API ##

La signature de la fonction random cryptographique à fournir :

```
void sg_random(uint8_t *dst, size_t len);
```

Cette fonction créé l'objet sg. Si les clefs sont vides, elles sont générés. Elle doivent être sauvé en flash.

```
void sg_init(sg_t *sg, uint8_t static_priv[SG_KEY_LEN], uint8_t psk[SG_PSK_LEN]);
```

Cette fonction récopie la clef privé.

```
void sg_get_static_priv(sg_t *sg,  uint8_t static_priv_in[SG_KEY_LEN]);
```
Il s'agit des 2 fonctions pour créer la session cryptographique. Attention les tailles augmentent.
```
int sg_handshake_make(sg_t *sg, sg_session_t *sg_session, uint8_t out[SG_MAX_FRAME]);
int sg_handshake_recv(sg_t *sg, sg_session_t *sg_session, const uint8_t *in, size_t in_len);
```
Et voici les 2 fonctions read et write "en place" pour chiffrer/déchiffrer
```
int sg_encrypt(sg_session_t *sess, uint8_t *frame, size_t *len_io);
int sg_decrypt(sg_session_t *sess, uint8_t *frame, size_t *len_io);
```

Ces fonctions sont utiles pour envoyer un message "one shot" avec seulement la clef public du récepteur. Il y a 100 octets d'overhead. 

```
size_t sg_decrypt_event(sg_t *sg,
    uint8_t frame[static SG_MAX_FRAME],
    size_t *frame_size);
size_t sg_encrypt_event(sg_t *sg, 
    uint8_t frame[static SG_MAX_FRAME],
    size_t *frame_size,
    const uint8_t peer_pub[SG_KEY_LEN]);`
```
## Schéma cryptographique ##

Pour la communication bidirectionnelle : 
* une clef statique qui identifie l'émetteur sur le long terme
* une clef ephémère pour le handshake
* une clef de session déduit des autres clefs et de la PSK.

Pour les event/messages :
* une clef statique qui identifie l'émetteur sur le long terme
* une clef ephémère générée et diffusée avec le message.
* une clef de session déduit des clefs et de la PSK.