# Accès à distance (version custom)

L'accès à distance permet d'utiliser l'iPhone ou l'iPad comme écran du Mac
**hors du réseau local** : depuis la 4G/5G, un autre WiFi, etc. Ce document
est le guide utilisateur et le modèle de sécurité. Le format exact des
messages est spécifié dans [PROTOCOL.md](../PROTOCOL.md), section 2.4.

> Les noms de boutons et de réglages cités ici peuvent différer légèrement de
> ceux de l'app ; le principe et l'ordre des étapes, eux, ne changent pas.

## En bref

* En local, le Mac appelle l'appareil. À distance c'est **l'inverse** :
  le **Mac écoute** sur le port TCP **9010** (modifiable, **désactivé par
  défaut**) et **l'appareil appelle** le Mac. Un téléphone en 4G/5G est
  derrière le NAT de l'opérateur et ne peut pas être joint, d'où ce sens.
* L'appairage pour l'accès à distance se fait **uniquement par câble USB**.
  L'appairage WiFi par code (section « Encrypted pairing » du README) ne
  donne **pas** l'accès à distance.
* Chaque Mac et chaque appareil possède une clé dans sa **Secure Enclave**,
  impossible à extraire, à sauvegarder ou à migrer. Sans Secure Enclave,
  pas d'accès à distance.
* Chaque session est chiffrée (TLS 1.2 avec une clé partagée propre à
  l'appairage) **et** signée par la Secure Enclave des deux côtés, avec une
  signature liée à cette session TLS précise.
* Réservé au couple **Mac (app d'envoi) ↔ iPhone/iPad**. L'app *OpenDisplay
  Receiver* pour Mac ne fait pas d'accès à distance.

## Prérequis

* **Mac avec Secure Enclave** : Mac Apple Silicon, ou Mac Intel avec puce
  T2. Un Mac Intel sans T2 ne peut pas proposer l'accès à distance.
* **iPhone/iPad** : tous les appareils compatibles iOS 15 ont une Secure
  Enclave.
* Les apps **custom** des deux côtés, de la même version.
* Un **chemin réseau** de l'appareil vers le Mac :
  * soit de l'**IPv6 entrant** jusqu'au Mac (à vérifier, voir ci-dessous) ;
  * soit **Tailscale** (ou un réseau overlay équivalent) sur les deux.

  L'IPv4 n'est pas une option avec une box en **CGNAT** (c'est le cas de la
  Bouygues 5G Box : l'adresse IPv4 publique est partagée avec d'autres
  abonnés, aucune redirection de port n'est possible).
* Le Mac doit être **allumé et éveillé** pendant l'utilisation (voir
  Dépannage).

## 1. Vérifier que la box laisse passer l'IPv6 entrant

À faire **avant tout le reste** : si la box filtre l'IPv6 entrant, seul
Tailscale fonctionnera. Ce test n'utilise pas OpenDisplay, juste un petit
serveur web temporaire sur le Mac.

1. **Trouver l'adresse IPv6 stable du Mac.** Dans le Terminal :

   ```sh
   ifconfig | grep inet6 | grep -v fe80 | grep secured
   ```

   Exemple de résultat :

   ```
   inet6 2001:db8:1234:5678:abcd:ef01:2345:6789 prefixlen 64 autoconf secured
   ```

   Gardez l'adresse (ici `2001:db8:1234:5678:abcd:ef01:2345:6789`).
   L'adresse marquée `secured` est l'adresse stable du Mac ; celles marquées
   `temporary` changent régulièrement et ne doivent pas servir. Aucune
   ligne ? Le Mac n'a pas d'IPv6 global : vérifiez que l'IPv6 est activé
   dans la box et dans Réglages Système → Réseau → (interface) → Détails →
   TCP/IP → « Configurer IPv6 : Automatiquement ».

2. **Lancer un serveur web de test sur le port 9010**, depuis un dossier
   **vide** (le serveur publie le contenu du dossier courant sur Internet :
   ne le lancez jamais depuis votre dossier personnel) :

   ```sh
   mkdir /tmp/vide && cd /tmp/vide && python3 -m http.server 9010 --bind ::
   ```

   Si macOS demande d'**autoriser les connexions entrantes** pour `python3`,
   acceptez pour la durée du test.

3. **Depuis l'iPhone, en données cellulaires, WiFi coupé**, ouvrez Safari à
   l'adresse (les crochets sont obligatoires) :

   ```
   http://[2001:db8:1234:5678:abcd:ef01:2345:6789]:9010
   ```

   * Une page « Directory listing for / » vide s'affiche, et le Terminal du
     Mac affiche une ligne `GET /` : **l'IPv6 entrant passe**. L'accès à
     distance direct est possible.
   * La page tourne puis échoue (délai dépassé) : **la box (ou l'opérateur)
     filtre l'IPv6 entrant**. Si l'interface d'administration de la box
     propose un réglage de pare-feu IPv6, essayez de l'assouplir pour le
     port 9010 vers le Mac, puis refaites le test. Sinon, utilisez
     Tailscale (section 6).
   * Safari dit tout de suite que l'adresse est injoignable : le téléphone
     n'a sans doute pas d'IPv6 en cellulaire. Vérifiez sur l'iPhone, toujours
     en cellulaire, avec [test-ipv6.com](https://test-ipv6.com).

4. **Vérifier aussi l'IPv6 du Mac** en ouvrant
   [test-ipv6.com](https://test-ipv6.com) sur le Mac : le score doit
   indiquer une connectivité IPv6.

5. **Arrêter le test** : `Ctrl-C` dans le Terminal, puis

   ```sh
   cd ~ && rmdir /tmp/vide
   ```

   Si vous aviez autorisé `python3` dans le coupe-feu, vous pouvez le retirer
   dans Réglages Système → Réseau → Coupe-feu → Options.

## 2. Activer l'accès à distance sur le Mac

1. Dans l'app Mac, ouvrez les réglages d'**accès à distance** et activez-le.
   Laissez le port **9010** sauf raison particulière (si vous le changez,
   refaites le test de la section 1 avec ce port).
2. Si le coupe-feu de macOS est actif, macOS demande d'**autoriser les
   connexions entrantes** pour OpenDisplay : acceptez. Si vous avez refusé
   par erreur : Réglages Système → Réseau → Coupe-feu → Options, passez
   OpenDisplay sur « Autoriser les connexions entrantes ».
3. Pour vérifier que le Mac écoute :

   ```sh
   lsof -nP -iTCP:9010 -sTCP:LISTEN
   ```

Le port n'est pas annoncé sur le réseau (pas de Bonjour). Tant que
l'accès à distance est désactivé, rien n'écoute.

## 3. Appairer l'appareil par USB

À faire une fois par appareil, avec le câble, à la maison.

1. Branchez l'iPhone/iPad au Mac avec un câble **données**, déverrouillez-le,
   acceptez « Faire confiance à cet ordinateur » si la question apparaît.
2. **Sur l'appareil**, ouvrez l'écran d'appairage pour l'**accès à
   distance** (réglages de l'app). L'appareil attend le Mac pendant
   **120 secondes** ; il n'écoute que par le câble.
3. **Sur le Mac**, lancez l'appairage d'accès à distance pour cet appareil.
4. Les **deux écrans affichent un code à 6 chiffres**. Vérifiez qu'il est
   **identique** sur les deux, puis **acceptez sur le Mac et sur
   l'appareil**. Codes différents : refusez des deux côtés.
5. C'est fait. Le Mac a transmis à l'appareil ses adresses et son port.

Refaites l'appairage si l'un des deux a été restauré, migré ou réinitialisé
(sa clé Secure Enclave a changé), ou après un « Oublier ».

## 4. Se connecter à distance

1. Hors de chez vous, ouvrez l'app sur l'appareil et choisissez le Mac dans
   la partie **accès à distance**.
2. L'appareil appelle le Mac, les deux s'authentifient, puis la session
   démarre comme d'habitude.
3. Le Mac affiche une **notification** à chaque session distante, avec le nom
   de l'appareil. Une notification inattendue = allez voir.

Différences avec une session locale : la session tolère **15 secondes**
sans données (au lieu de 5) pour passer les coupures cellulaires, c'est
**l'appareil qui se reconnecte** après une coupure (le Mac ne peut pas
l'appeler), et le curseur passe par la connexion principale (pas de canal
UDP).

### Changement d'adresse du Mac

Le préfixe IPv6 attribué par la box peut changer (redémarrage, opérateur).
Le Mac renvoie automatiquement ses adresses à l'appareil à chaque session
(USB, WiFi appairé ou distante). Si le préfixe change pendant que vous êtes
dehors **sans session ouverte**, l'appareil ne retrouvera pas le Mac avant
la prochaine session à la maison (USB ou WiFi suffit, pas besoin de
réappairer). Tailscale évite ce problème : l'adresse Tailscale ne change pas.

## 5. Ce qui est protégé, et les limites

### Protégé

* **Le port ouvert sur Internet ne révèle rien.** Sur le port 9010, le Mac
  ne parle que TLS avec clé pré-partagée : sans la clé d'un appairage, la
  poignée de main échoue. Une connexion qui n'aboutit pas est fermée en
  quelques secondes. Même avec une poignée de main réussie, le Mac ne lit
  qu'**un seul message d'au plus 1 Ko**, dans un délai de **5 secondes**, et
  ferme sans rien répondre si la signature n'est pas valable. Aucun écran,
  aucune entrée clavier/souris avant cela.
* **Copier le trousseau ne suffit pas.** La clé de session est scellée par
  une clé de la Secure Enclave ; copiée sur une autre machine, elle est
  inutilisable. Et la signature exigée à chaque session ne peut être faite
  que par la Secure Enclave d'origine.
* **Mac migré ou restauré, iPad restauré : refusés.** La Secure Enclave
  d'une nouvelle machine contient une autre clé ; il faut réappairer par USB.
* **Pas de rejeu ni de relais.** La signature couvre une valeur extraite de
  la session TLS en cours (RFC 5705) : elle ne vaut pour aucune autre
  session.
* **Un appareil appairé à un autre Mac est refusé**, tout comme un appareil
  appairé seulement par code WiFi.
* **Oublier coupe immédiatement.** « Oublier » un appareil sur le Mac retire
  sa clé et coupe une session en cours.
* **Pas de tiers.** Aucune connexion ne passe par un serveur d'OpenDisplay ;
  avec Tailscale, le trafic transite par Tailscale mais reste chiffré et
  authentifié par OpenDisplay en plus.

### Limites connues

* **Pas de confidentialité persistante (forward secrecy).** TLS 1.2 avec clé
  pré-partagée n'en offre pas : quelqu'un qui aurait enregistré vos sessions
  **et** obtiendrait plus tard la clé de cet appairage pourrait les
  déchiffrer. La clé étant scellée par la Secure Enclave, c'est difficile ;
  le script de test vérifie si TLS 1.3 avec PSK (qui corrige ce point) est
  utilisable.
* **Un logiciel malveillant sur l'appareil déverrouillé** (ou sur le Mac)
  peut se servir de la clé Secure Enclave sur place, sans pouvoir la copier.
* **L'existence du port est visible** par un scan, et un attaquant peut
  occuper le port (déni de service) sans pouvoir se connecter.
* **IPv4 impossible derrière CGNAT** : IPv6 entrant ou Tailscale.
* **Le Mac doit rester éveillé.**

## 6. Alternative : Tailscale

Si la box filtre l'IPv6 entrant (ou pour ne rien exposer sur Internet) :

1. Installez **Tailscale** sur le Mac et sur l'iPhone/iPad, connectés au
   même tailnet.
2. Notez l'adresse Tailscale du Mac (`100.x.y.z`, ou son nom MagicDNS, du
   type `mon-mac.xxxx.ts.net`), visible dans l'app Tailscale.
3. L'app OpenDisplay ne change pas : l'adresse Tailscale est une adresse
   comme une autre. Vérifiez dans les réglages d'accès à distance du Mac
   qu'elle figure parmi les adresses transmises à l'appareil ; si ce n'est
   pas le cas, ajoutez-la (si le réglage le permet), puis reconnectez une
   fois l'appareil en USB ou WiFi pour qu'il la reçoive.
4. Sur l'appareil, activez le VPN Tailscale avant de lancer la connexion.

Avec Tailscale seul, vous pouvez restreindre le coupe-feu du Mac pour que le
port 9010 ne soit joignable que depuis l'interface Tailscale.

## 7. Dépannage

| Symptôme | Causes probables |
|---|---|
| Option d'accès à distance absente ou grisée | Pas de Secure Enclave sur le Mac ou l'appareil (Mac Intel sans T2), ou app Mac *Receiver* |
| L'appareil ne voit pas le Mac pendant l'appairage USB | Écran d'appairage pas ouvert sur l'appareil, délai de 120 s écoulé, câble charge seule, appareil verrouillé ou « Faire confiance » non accepté |
| Connexion distante : délai dépassé | Box qui filtre l'IPv6 entrant (refaire la section 1), Mac en veille, accès à distance désactivé, coupe-feu macOS, préfixe IPv6 changé (voir section 4), appareil sans IPv6 en cellulaire |
| Connexion distante : refus immédiat ou échec TLS | Appairage oublié d'un côté, Mac ou appareil restauré/migré : réappairer en USB |
| Coupures fréquentes | Réseau cellulaire faible : la session survit à une coupure de moins de ~15 s, l'appareil se reconnecte seul ensuite |
| Le Mac se met en veille | Réglages Système → Écran/Batterie → Options : empêcher la suspension automatique sur secteur, ou activer « Réactiver pour l'accès réseau » (non suffisant seul pour une connexion entrante IPv6 : garder le Mac éveillé est plus fiable) |

**Journaux** : sur le Mac, bouton **Logs** (dossier
`~/Library/Logs/OpenDisplay`) ; sur l'appareil, secouer → **Connection
log**. Les refus d'authentification y sont consignés.

## 8. Vérifications préalables (spike)

Avant de compter sur la fonction sur un nouveau Mac ou une nouvelle version
de macOS, lancez sur le Mac :

```sh
swift tools/remote-spike.swift
```

Le script vérifie la Secure Enclave (création de clé, signature,
persistance, accord de clé), une session TLS 1.2 PSK en boucle locale avec
l'exporteur RFC 5705 identique des deux côtés et le refus d'une mauvaise
clé, puis essaie TLS 1.3 PSK (informatif). Il affiche `PASS` / `FAIL` /
`INFO` et sort avec le code 1 en cas d'échec. Si la partie Secure Enclave
échoue dans le script, refaites le test depuis l'app signée avant de
conclure (un script non signé peut se comporter autrement).

Résultats à consigner :

| Date | Mac / macOS | Secure Enclave | TLS 1.2 PSK + exporteur | Mauvaise clé refusée | TLS 1.3 PSK | Remarques |
|---|---|---|---|---|---|---|
| | | | | | | |

## 9. Recette manuelle

À dérouler avant de considérer l'accès à distance comme utilisable, puis
après tout changement touchant l'appairage, TLS ou l'authentification.
Pour chaque test, noter la date, les versions et le résultat ; consulter
les journaux des deux côtés en cas de doute.

- [ ] **Spike** : `swift tools/remote-spike.swift` passe sur le Mac
  d'envoi ; résultats recopiés dans le tableau de la section 8.
- [ ] **Refus avant appairage USB** : accès à distance activé sur le Mac,
  appareil jamais appairé en USB. L'appareil ne propose pas ce Mac en
  accès à distance, et une connexion forcée vers le port échoue à la
  poignée de main TLS. Aucune session, aucune notification sur le Mac.
- [ ] **L'appairage WiFi par code ne donne pas l'accès à distance** :
  appareil appairé uniquement par code WiFi. Le Mac ne le liste pas parmi
  les appareils d'accès à distance ; l'appareil ne propose pas le Mac en
  accès à distance ; la session WiFi locale, elle, fonctionne.
- [ ] **Mac migré / trousseau copié refusé** : migrer le Mac appairé vers un
  autre Mac (Assistant migration ou restauration Time Machine), activer
  l'accès à distance sur le nouveau, faire pointer l'appareil vers lui (même
  adresse/port ou relais `socat`, voir plus bas). Connexion refusée
  (poignée de main ou `rauth` en échec) ; il faut un nouvel appairage USB.
- [ ] **iPad restauré refusé** : restaurer l'iPad depuis une sauvegarde
  (chiffrée, pour que le trousseau suive autant que possible) puis tenter
  une connexion distante. Aucune entrée d'accès à distance utilisable, ou
  refus par le Mac. Un nouvel appairage USB rétablit l'accès.
- [ ] **iPad appairé à un autre Mac refusé** : appairer l'iPad en USB avec le
  Mac B seulement. Désactiver l'accès à distance sur B et y lancer un relais
  vers le Mac A (`brew install socat`, puis
  `socat TCP6-LISTEN:9010,fork,reuseaddr TCP6:[adresse-de-A]:9010`). Depuis
  l'iPad, se connecter à B : le trafic arrive sur A, qui **refuse**
  (identité PSK inconnue, poignée de main en échec). Ce test vérifie aussi
  qu'un relais ne sert à rien.
- [ ] **« Oublier » coupe la session en cours** : pendant une session
  distante, oublier l'appareil sur le Mac. La session s'arrête dans la
  seconde, les tentatives de reconnexion de l'appareil échouent. Refaire
  dans l'autre sens : oublier le Mac sur l'appareil, qui cesse d'appeler.
- [ ] **Un scan du port 9010 ne révèle rien avant authentification**, depuis
  une machine extérieure (autre réseau, partage de connexion cellulaire,
  serveur distant) :
  - `nc -6 -v ADRESSE 9010` sans rien taper : la connexion TCP s'ouvre puis
    est **fermée par le Mac en 5 s environ**, sans aucun octet reçu ;
  - `openssl s_client -connect '[ADRESSE]:9010'` : échec de la poignée de
    main (pas de suite commune), connexion fermée ;
  - `openssl s_client -connect '[ADRESSE]:9010' -tls1_2 -cipher PSK-AES128-GCM-SHA256 -psk_identity 00000000000000000000000000000000 -psk 00`
    : échec de la poignée de main ;
  - optionnel : `nmap -6 -sV -p 9010 ADRESSE` ne donne ni bannière ni nom de
    service.
  Le Mac n'affiche aucune notification et ne crée aucun écran.
- [ ] **La session survit à une courte coupure cellulaire** : pendant une
  session distante, mode Avion 5 s puis retour. L'appareil se reconnecte
  seul et l'écran reprend (même bureau) ; une coupure nettement plus longue
  que la période de grâce termine proprement la session.
- [ ] **Notification** : chaque session distante authentifiée affiche une
  notification sur le Mac avec le nom de l'appareil.
- [ ] **Adresse mise à jour** : après un changement de préfixe IPv6 (ou un
  ajout d'adresse Tailscale), une session USB ou WiFi suffit pour que
  l'appareil retrouve le Mac à distance, sans réappairage.
- [ ] **Accès à distance désactivé** : rien n'écoute sur le port
  (`lsof -nP -iTCP:9010 -sTCP:LISTEN` vide), l'appareil échoue proprement.
