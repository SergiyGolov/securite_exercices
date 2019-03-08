#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# source pour l'algo: https://hcsw.org/reading/chalresp.txt
import hashlib
import secrets
import string
from datetime import datetime, timedelta
import time

# TODO: tester d'utiliser directement le module python hmac pour hasher challenge+password ? https://docs.python.org/2/library/hmac.html
# TODO: utiliser https://docs.python.org/3/library/hashlib.html#key-derivation pour stocker les mdp ? quoi que, on a vu en cours que ça ne changait rien il me semble


class Common(object):
    def __init__(self):
        pass

    def hash(self, m):
        # utilisation de sha256 car le hash résultat est assez long pour éviter les collisions mais pas "trop" long comme dans le cas de sha512
        return hashlib.sha256(str.encode(m)).hexdigest()

    def hashChallengePasswordConcatenation(self, challenge, password):
        return self.hash(challenge+password)


class Server(Common):
    def __init__(self, nonce_expiration_limit=1):
        # precaution pour l'unicité du nonce: on garde en mémoire les nonce, et on vérifie qu'ils ne soient pas utilisé plus d'une fois
        # dictionnaire avec comme clé le challenge et comme valeur un booléen indiquant s'il a déjà été utilisé par un client ou pas
        self.used_nonce = {}

        # precaution pour la durée de validité du nonce
        self.nonce_expiration = {}

        # limite d'expiration du nonce en secondes
        self.nonce_expiration_limit = nonce_expiration_limit

    def generateSecureRandomString(self, stringLength=16):
        # precaution pour le générateur aléatoire: utilisation de modules python spécifiques
        # source: https://pynative.com/python-generate-random-string/ chapitre "Use_The_Secrets_module_to_generate_a_secure_random_string"
        """Generate a secure random string of letters, digits and special characters """
        password_characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(password_characters) for i in range(stringLength))

    def generateChallenge(self):
        challenge = self.generateSecureRandomString()
        self.used_nonce[challenge] = False
        self.nonce_expiration[challenge] = datetime.today() + timedelta(seconds=self.nonce_expiration_limit)
        return challenge

    def checkNonceExpiration(self, challenge):
        return datetime.today() < self.nonce_expiration[challenge]

    def checkResponse(self, response, password, challenge):
        isResponseOK = response == self.hashChallengePasswordConcatenation(challenge, password)

        isResponseNotTooLate = self.checkNonceExpiration(challenge)

        # si la réponse est juste et que le nonce n'a pas encore été utilisé et si le nonce n'est pas expiré, c'est OK
        if isResponseOK and not self.used_nonce[challenge] and isResponseNotTooLate:
            self.used_nonce[challenge] = True
        elif isResponseOK and not isResponseNotTooLate:  # si le nonce était déjà expiré
            raise Exception("The nonce is already expired")
        elif isResponseOK:  # si la réponse est juste et que le nonce a déjà été utilisé
            raise Exception("The nonce has already been used")

        return isResponseOK


class Client(Common):
    def __init__(self):
        pass

    def generateResponse(self, challenge, password):
        return self.hashChallengePasswordConcatenation(challenge, password)


if __name__ == "__main__":
    # On part du principe que le mot de passe a déjà été partagé entre le client et le serveur
    # (Entropy: 141.3 bits, source: http://rumkin.com/tools/password/passchk.php)
    PASSWORD = "laChaiseEstRougeLesFraisesAussi"

    server = Server(nonce_expiration_limit=1)
    client = Client()

    for i in range(1, 11):
        print(f"Test {i}:")

        # 1. The client connects to the server.
        pass

        # 2. The server makes up some random data
        challenge = server.generateChallenge()
        print(f"\tserver challenge: {challenge}")

        # 3. The server sends this data to client
        pass

        # 4. The client concatenates the random data with the password
        print(f"\tchallenge + password concatenation: {challenge+PASSWORD}")

        # 5. The client computes the hash of this value
        response = client.generateResponse(challenge, PASSWORD)
        print(f"\tclient hashed response: {response}")

        # 6. The client sends the resulting hash to the server
        pass

        # 7. The server runs the same command, and since the server (hopefully) got the same result, it lets the user in.
        print(f"\tResponse = challenge? {server.checkResponse(response,PASSWORD,challenge)}\n")


    # Test de la garantie de l'unicité du nonce (devrait renvoyer une exception)
    #server.checkResponse(client.generateResponse(challenge, PASSWORD), PASSWORD,challenge)

    # Test de la limite d'expiration du nonce (devrait renvoyer une exception)
    #time.sleep(1)
    #server.checkResponse(client.generateResponse(challenge, PASSWORD), PASSWORD,challenge)
