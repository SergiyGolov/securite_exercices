#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Exercice    : Challenge-Response
Donnée      : https://ssl.horus.ch/~schaefer/bin/view/HEArc/SecuriteINF3ExercicesAuthentification#4_Exercice_rendre_challenge_resp
Cours       : Securité, Marc Schaeffer
Organisation: HE-Arc Ingénierie, Neuchâtel
Autors      : Kim Aurore Biloni & Sergiy Goloviatinski
Date        : 10.03.2019
"""

import hashlib
import secrets
import string
from datetime import datetime, timedelta
import time
import random

###
### Classe utilitaire commune
###
class Common(object):
    """Classe utilitaire de hashage avec sha256"""
    def __init__(self):
        pass

    def hash(self, m):
        """utilisation de sha256 car le hash résultat est assez long pour éviter les collisions mais pas "trop" long comme dans le cas de sha512"""
        return hashlib.sha256(str.encode(m)).hexdigest()

    def hashChallengePasswordConcatenation(self, challenge, password):
        """retourne le hash de la concatenation du challenge et du password"""
        return self.hash(challenge+password)


###
### Classe du serveur
###
class Server(Common):
    """Class Server"""
    def __init__(self, nonce_expiration_limit=1):
        # precaution pour l'unicité du nonce: on garde en mémoire les nonce, et on vérifie qu'ils ne soient pas utilisé plus d'une fois
        # dictionnaire avec comme clé le challenge et comme valeur un booléen indiquant s'il a déjà été utilisé par un client ou pas
        self.used_nonce = {}

        # precaution pour la durée de validité du nonce
        self.nonce_expiration = {}

        # limite d'expiration du nonce en secondes
        self.nonce_expiration_limit = nonce_expiration_limit

        # dictionnaire de clients connus avec comme clé le client et comme valeur le mot de passe
        self.clientsKnown = {}

        # dictionnaire de clients et leur challenge avec comme clé le client et comme valeur le challenge
        self.clientsChallenge = {}


    def generateSecureRandomString(self, stringLength=16):
        # precaution pour le générateur aléatoire: utilisation de modules python spécifiques
        # source: https://pynative.com/python-generate-random-string/ chapitre "Use_The_Secrets_module_to_generate_a_secure_random_string"
        """Generate a secure random string of letters, digits and special characters """
        password_characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(password_characters) for i in range(stringLength))

    def generateChallenge(self):
        """Genère un nouveau challenge"""
        challenge = self.generateSecureRandomString()
        self.used_nonce[challenge] = False
        self.nonce_expiration[challenge] = datetime.today() + timedelta(seconds=self.nonce_expiration_limit)
        return challenge

    def generateChallengeForClient(self, client):
        """Genère un challenge pour un client"""
        try:
            # Recupère le challenge précédemment donné à un client
            challenge = self.clientsChallenge[client]

            # Vérification de la validité du challenge
            if not self.checkNonceExpiration(challenge):
                # Sinon en genère un nouveau
                challenge = self.generateChallenge()
        except KeyError:
            # Si aucun challenge a été généré, en recréer un
            challenge = self.generateChallenge()
        # Ajoute le challenge dans le dictionnaire
        self.clientsChallenge[client] = challenge

        return challenge

    def checkNonceExpiration(self, challenge):
        """Vérification de l'expiration du nonce"""
        return datetime.today() < self.nonce_expiration[challenge]

    def checkResponse(self, response, challenge, password):
        """
        Vérfication de la reponse envoyer compararé au hash de la concatenation
        du challenge et du password
        """
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

    def checkResponseClient(self, response, client):
        """
        Vérfication de la reponse envoyée et des données d'un client
        stockées par le serveur 
        """
        try:
            clientChallenge = self.clientsChallenge[client]
            clientPassword = self.clientsKnown[client]
            return self.checkResponse(response, clientChallenge, clientPassword)
        except KeyError:
            print("Le client est inconnu du serveur")
    
    def addClient(self, client, password):
        """
        Ajoute un client et son password au dictionnaire des clients
        connus par le serveur
        """
        self.clientsKnown[client] = password


###
### Classe du client
###
class Client(Common):
    """Class Client"""
    def __init__(self):
        # Dictionaire de serveurs connus avec comme clé le serveur et comme valeur le mot de passe
        self.serversKnown = {}

    def generateResponse(self, challenge, password):
        """ Genère un hash de la concaténation du challenge et du mot de passe"""
        return self.hashChallengePasswordConcatenation(challenge, password)


    def generateResponseForServer(self, challenge, server):
        try:
            serverPassword = self.serversKnown[server]
            return self.generateResponse(challenge, serverPassword)
        except KeyError:
            raise Exception("The server is unknow of the client")


    def addServer(self, server, password):
        """Ajoute un serveur et son password au dictionnaire des serveurs connus par le client"""
        self.serversKnown[server] = password



###
### Fonctions de tests
###
def singleServerClientTest():
    '''
    Test challenge-response utilisant un seul client et un seul serveur.
    On part du principe qu'ils se connaissent déjà l'un l'autre.
    '''

    print("Single client-server challenge-response")

    client = Client()
    server = Server(nonce_expiration_limit=1)

    # (Entropy: 141.3 bits, source: http://rumkin.com/tools/password/passchk.php)
    PASSWORD = "laChaiseEstRougeLesFraisesAussi"

    client.addServer(server, PASSWORD)
    server.addClient(client, PASSWORD)

    # 1. The client connects to the server.
    pass

    # 2. The server makes up some random data
    challenge = server.generateChallenge()
    print(f"\tserver challenge: {challenge}")

    # 3. The server sends this data to client
    pass

    # 4. The client concatenates the random data with the password
    serverPassword = client.serversKnown[server]
    print(f"\tchallenge + password concatenation: {challenge + serverPassword}")

    # 5. The client computes the hash of this value
    response = client.generateResponse(challenge, serverPassword)
    print(f"\tclient hashed response: {response}")

    # 6. The client sends the resulting hash to the server
    pass

    # 7. The server runs the same command, and since the server (hopefully) got the same result, it lets the user in.
    clientPassword = server.clientsKnown[client]
    print(f"\tResponse = challenge? {server.checkResponse(response, challenge, clientPassword)}\n")

    # Test de la garantie de l'unicité du nonce (devrait renvoyer une exception)
    try:
        server.checkResponse(client.generateResponse(challenge, PASSWORD), challenge, clientPassword)
    except Exception as e:
        print(e)

    # Test de la limite d'expiration du nonce (devrait renvoyer une exception)

    time.sleep(1)
    try:
        server.checkResponse(client.generateResponse(challenge, PASSWORD), challenge, clientPassword)
    except Exception as e:
        print(e)



def generateClientsServers(passwordList, nb_clients=10, nb_servers=3):
    '''
    Genère un dictionnaire de clients et un dictionnaire de serveurs
    à partir d'une liste de mot de passe.
    Un client connaît un certain nombre de serveurs.
    '''
    # list of clients
    clients = []
    # list of servers
    servers = [Server() for srv in range(nb_servers)]

    for i in range(len(passwordList)):
        # Create the new client
        cl = Client()
        clients.append(cl)

        # Choose how many servers the client knows
        nb_serversKnown = random.randint(1, nb_servers)

        # for the number of known servers by the client
        for j in range(nb_serversKnown):
            # choose a random server
            server = random.choice(servers)
            
            # choose a random password
            password = random.choice(passwordList)

            # create the relation between the client and the server
            cl.addServer(server, password)
            server.addClient(cl, password)

    return clients, servers


def multiClientsServersTest():
    '''
    Genère des clients et servers aléatoirement et essaie de les
    connecter entre eux.
    '''

    print("Multi clients-servers challenge response")

    PASSWORDS = [
        "laChaiseEstRougeLesFraisesAussi",
        "LeVioletEstUneJolieCouleur",
        "JeVousConseilleDEcouterLeGroupePalace",
        "CestDeLaMusiqueTresAgreablePourUneDimanchePluvieux",
        "LeoWyndhamMattHodgesAndRupertTurner",
    ]

    clients,servers = generateClientsServers(PASSWORDS)

    for i in range(1, 11):
        print(f"Test {i}:")
        # Selection d'un client et d'un serveur
        server = random.choice(servers)
        client = random.choice(list(server.clientsKnown.keys()))
        

        supposedServerPassword = None
        try:
            supposedServerPassword = client.serversKnown[server]
        except KeyError:
            break

        # 1. The client connects to the server.
        pass

        # 2. The server makes up some random data
        challenge = server.generateChallenge()
        print(f"\tserver challenge: {challenge}")

        # 3. The server sends this data to client
        pass

        # 4. The client concatenates the random data with the password
        print(f"\tchallenge + password concatenation: {challenge + supposedServerPassword}")

        # 5. The client computes the hash of this value
        response = client.generateResponse(challenge, supposedServerPassword)
        print(f"\tclient hashed response: {response}")

        # 6. The client sends the resulting hash to the server
        pass

        # 7. The server runs the same command, and since the server (hopefully) got the same result, it lets the user in.
        try:
            clientPassword = server.clientsKnown[client]
            result = server.checkResponse(response, challenge, clientPassword)
        except:
            result = False
        print(f"\tResponse = challenge? {result}\n")


def singleServerClientUsingServerKnowledgeTest():
    '''
    Test challenge-response utilisant un seul client et un seul serveur.
    On utilise les dictionnaires pour générer les challenges et les réponses.
    '''

    print("Single client-server challenge-response using knowledge")

    client = Client()
    server = Server(nonce_expiration_limit=1)

    # (Entropy: 141.3 bits, source: http://rumkin.com/tools/password/passchk.php)
    PASSWORD = "laChaiseEstRougeLesFraisesAussi"

    client.addServer(server, PASSWORD)
    server.addClient(client, PASSWORD)

    # 1. The client connects to the server.
    pass

    # 2. The server makes up some random data for a client
    challenge = server.generateChallengeForClient(client)
    print(f"\tserver challenge: {challenge}")

    # 3. The server sends this data to client
    pass

    # 4. The client concatenates the random data with the password
    serverPassword = client.serversKnown[server]
    print(f"\tchallenge + password concatenation: {challenge + serverPassword}")

    # 5. The client computes the hash of this value
    response = client.generateResponseForServer(challenge, server)
    print(f"\tclient hashed response: {response}")

    # 6. The client sends the resulting hash to the server
    pass

    # 7. The server runs the same command, and since the server (hopefully) got the same result, it lets the user in.
    print(f"\tResponse = challenge? {server.checkResponseClient(response, client)}\n")


if __name__ == "__main__":

    # Test de plusieurs clients-serveurs
    multiClientsServersTest()

    # Test d'un seul échange client-serveur mais avec connaissance
    singleServerClientUsingServerKnowledgeTest()

    # Test d'un seul échange client-serveur, avec gestion des erreurs liés au nonce déjà validé ou nonce déjà expiré
    singleServerClientTest()
