# ZTSSH Protocol Specification v0.2

## Zero Trust SSH — Continuous Session Identity Verification

### 1. Résumé

ZTSSH est un protocole SSH augmenté qui implémente la **vérification continue de l'identité** pendant toute la durée d'une session. Contrairement à OpenSSH standard (authentification au login uniquement), ZTSSH revalide l'identité du client toutes les N secondes via un mécanisme de renouvellement de certificats courts, sans nécessiter d'appel réseau pendant la session.

### 2. Principes Zero Trust appliqués

| Principe | Implémentation ZTSSH |
|---|---|
| Ne jamais faire confiance, toujours vérifier | Revalidation toutes les 60s |
| Accès moindre privilège | Certificats à durée de vie 5 min |
| Supposer la compromission | Révocation instantanée sur 3 niveaux |
| Vérification continue | Keepalive identity intégré au protocole |
| Résilience aux pannes | Sub-CA local, pas de dépendance réseau en session |

### 3. Architecture hiérarchique

```
                        ┌──────────────┐
                        │   Root CA    │  OFFLINE (air-gapped)
                        │  (ztssh-ca)  │
                        └──────┬───────┘
                               │
                    issues IntermediateCertificate (24h)
                    + maintains global RevocationList
                               │
              ┌────────────────┼────────────────┐
              │                │                │
      ┌───────▼──────┐ ┌──────▼───────┐ ┌──────▼───────┐
      │  Server A    │ │  Server B    │ │  Server C    │
      │  Sub-CA      │ │  Sub-CA      │ │  Sub-CA      │
      │  (embedded)  │ │  (embedded)  │ │  (embedded)  │
      └───────┬──────┘ └──────┬───────┘ └──────┬───────┘
              │               │                │
        issues ZTSSHCert    issues ZTSSHCert   ...
           (5 min)           (5 min)
              │               │
      ┌───────▼──────┐ ┌─────▼────────┐
      │  Client      │ │  Client      │
      │  (ztssh)     │ │  (ztssh)     │
      └──────────────┘ └──────────────┘
```

#### 3.1 Composants

| Composant | Rôle | Durée de vie | Connectivité |
|---|---|---|---|
| **Root CA** | Émet les licences serveur, gère la révocation globale | Permanent (offline) | Hors-ligne (air-gapped) |
| **Sub-CA** | Émet les badges client, vérifie les preuves | Tant que le serveur tourne | Local uniquement (embarqué) |
| **Client** | Détient un badge éphémère, répond aux challenges | Durée de la session | Vers le serveur uniquement |

#### 3.2 Types de certificats

| Type | Émetteur | Destinataire | TTL | Rôle |
|---|---|---|---|---|
| **IntermediateCertificate** | Root CA | Serveur (Sub-CA) | 24h | Licence d'exploitation (autorise le serveur à émettre) |
| **ZTSSHCertificate** | Sub-CA | Client | 5 min | Badge d'accès (prouve l'identité du client) |

#### 3.3 Flux de provisioning (hors session)

```
Admin ──► Root CA: "Autorise le serveur srv-01 pour les utilisateurs [alice, bob]"
         Root CA ──► Signe IntermediateCertificate (24h)
                     ──► Envoie au serveur srv-01

srv-01 installe l'IntermediateCertificate dans son Sub-CA embarqué
srv-01 est maintenant autorisé à émettre des badges pour alice et bob
```

#### 3.4 Flux de session (continu)

```
Client ──── auth initiale ────► Server Sub-CA
              │                      │
              │  ZTSSHCert (5 min)   │  Émission locale (0 réseau)
              │◄─────────────────────│
              │                      │
     ══ Boucle continue (60s) ══    │
              │                      │
     Server ──► IDENTITY_CHALLENGE   │
              │                      │
     Client ──► renouvelle cert (local)
              │──► signe challenge   │
              │──► IDENTITY_PROOF ──►│
              │                      │──► verify_certificate()
              │◄── IDENTITY_ACK ─────│  ou TERMINATE
              │                      │
     ══════════════════════════════ │
```

### 4. Messages du protocole

Le protocole ZTSSH définit les messages suivants, encapsulés dans le canal SSH existant :

#### 4.1 ZTSSH_IDENTITY_PROOF (Client → Server)

```
byte      SSH_MSG_ZTSSH_IDENTITY_PROOF  (0xC0)
uint32    sequence_number
uint64    timestamp
string    certificate                    # ZTSSHCertificate sérialisé (badge)
string    signature                      # Signature du challenge serveur
```

#### 4.2 ZTSSH_IDENTITY_CHALLENGE (Server → Client)

```
byte      SSH_MSG_ZTSSH_IDENTITY_CHALLENGE  (0xC1)
uint32    sequence_number
uint64    timestamp
string    nonce                           # Challenge aléatoire 32 bytes
uint32    deadline_seconds                # Temps pour répondre (défaut: 30s)
```

#### 4.3 ZTSSH_IDENTITY_ACK (Server → Client)

```
byte      SSH_MSG_ZTSSH_IDENTITY_ACK  (0xC2)
uint32    sequence_number
uint64    next_challenge_in_seconds       # Prochain challenge dans N secondes
```

#### 4.4 ZTSSH_SESSION_TERMINATE (Server → Client)

```
byte      SSH_MSG_ZTSSH_SESSION_TERMINATE  (0xC3)
uint32    sequence_number
uint32    reason_code
string    reason_message
```

#### 4.5 IntermediateCertificate (wire format)

Utilisé entre Root CA et serveurs pour le provisioning (hors session SSH).

```
bytes[21]  magic          "ZTSSH-INTERMEDIATE-V1"
uint32     serial
string     server_id
bytes[32]  subject_public_key   # Clé publique du Sub-CA
bytes[32]  issuer_public_key    # Clé publique du Root CA
uint32     num_principals
string[]   allowed_principals   # Liste ou ["*"] pour tous
float64    issued_at
float64    expires_at
bytes[64]  signature            # Ed25519 du Root CA
```

#### 4.6 ZTSSHCertificate (wire format)

Badge client émis par le Sub-CA.

```
bytes[14]  magic          "ZTSSH-CERT-V1"
uint32     serial
string     principal
bytes[32]  subject_public_key   # Clé éphémère du client
bytes[32]  issuer_public_key    # Clé du Sub-CA
float64    issued_at
float64    expires_at
bytes[64]  signature            # Ed25519 du Sub-CA
```

#### Codes de raison (TERMINATE)

| Code | Signification |
|------|--------------|
| 0x01 | CERT_EXPIRED — Certificat expiré sans renouvellement |
| 0x02 | CERT_REVOKED — Certificat révoqué par la CA |
| 0x03 | CHALLENGE_TIMEOUT — Pas de réponse au challenge |
| 0x04 | INVALID_PROOF — Preuve d'identité invalide |
| 0x05 | POLICY_VIOLATION — Changement de politique d'accès |
| 0x06 | ADMIN_REVOKE — Révocation manuelle par admin |

### 5. Cycle de vie d'un certificat

```
  Émission (t=0)
      │
      ▼
  ┌─────────────────────────────────┐
  │  Certificat valide              │
  │  TTL: 300s (5 minutes)          │
  │  Renewal window: 60s avant exp  │
  └─────────────────────────────────┘
      │                         │
      │ (t=240s) Renewal        │ (t=300s) Expiration
      ▼                         ▼
  ┌──────────┐            ┌──────────────┐
  │ Nouveau  │            │ Grace period │
  │ cert     │            │ 30s          │
  │ émis     │            └──────────────┘
  └──────────┘                  │
                                ▼
                          ┌──────────────┐
                          │ SESSION      │
                          │ TERMINATE    │
                          └──────────────┘
```

- **TTL du certificat** : 300 secondes (5 minutes)
- **Fenêtre de renouvellement** : commence 60 secondes avant expiration (à t=240s)
- **Grace period** : 30 secondes après expiration pour renouveler
- **Intervalle des challenges** : toutes les 60 secondes

### 6. Sécurité

#### 6.1 Modèle de révocation à 3 niveaux

| Niveau | Action | Effet | Propagation |
|---|---|---|---|
| **Root CA** | `ban_principal("hacker")` | Aucun serveur ne peut émettre de badge pour ce principal | Via RevocationList snapshot push |
| **Root CA** | `revoke_server(serial)` | Le serveur perd sa licence, ne peut plus émettre | Vérifié par Root lors des audits |
| **Sub-CA** | `revoke_client(serial)` | Un badge spécifique est invalidé sur ce serveur | Local, immédiat |

La `RevocationList` est maintenue par le Root CA et distribuée aux Sub-CAs via des snapshots :
```
Root CA ──► revocation_list.snapshot() ──► Sub-CA.update_revocation_list(snapshot)
```

Les snapshots sont des copies indépendantes : modifier la CRL après un snapshot n'affecte pas les copies déjà distribuées.

#### 6.2 Isolation multi-serveur

Chaque Sub-CA a sa propre paire de clés. Un certificat émis par le Sub-CA du serveur A **ne peut pas** être vérifié par le Sub-CA du serveur B (vérification `issuer_mismatch`). Cela empêche les mouvements latéraux entre serveurs en cas de compromission d'un badge.

#### 6.3 Protection contre les attaques

| Attaque | Protection ZTSSH |
|---|---|
| Clé compromise | Badge expire en 5 min max |
| Session hijacking | Challenge-response continu invalide le hijacker |
| Replay attack | Nonce unique + timestamp + sequence number |
| Man-in-the-middle | Chaîne de confiance Root → Sub-CA → Client |
| Appareil compromis | Révocation instantanée (3 niveaux) |
| Mouvement latéral | Isolation Sub-CA par serveur |
| Panne Root CA | Sub-CAs fonctionnent en autonome tant que la licence est valide |

#### 6.4 Crypto

- **Certificats** : Ed25519 (clés éphémères)
- **Signatures** : Ed25519
- **Nonces** : 32 bytes CSPRNG
- **Hash** : SHA-256 pour les challenges

### 7. Compatibilité

ZTSSH est conçu pour fonctionner **au-dessus** du protocole SSH standard :
- Les messages ZTSSH utilisent le range privé SSH (0xC0-0xCF)
- Un serveur OpenSSH standard ignore ces messages → connexion classique
- Un client ZTSSH vers un serveur non-ZTSSH → fonctionne en mode dégradé (SSH normal)
- La négociation ZTSSH se fait via SSH extension negotiation (RFC 8308)

### 8. Configuration

```toml
# ztssh.toml

[root_ca]
# Offline — utilisé uniquement pour le provisioning
intermediate_cert_ttl = 86400   # 24 heures (licence serveur)

[server]
# Sub-CA embarqué
intermediate_cert_path = "/etc/ztssh/intermediate.cert"
cert_ttl = 300                  # 5 minutes (badge client)
challenge_interval = 60         # toutes les 60 secondes
challenge_timeout = 30          # deadline pour répondre
terminate_on_failure = true
crl_update_interval = 300       # poll RevocationList toutes les 5 min

[client]
auto_renew = true
renewal_window = 60             # renouveler 60s avant expiration
```
