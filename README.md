# challenge-response

## idées d'amélioration

* faire un dictionnaire avec comme clé une instance de server (chez le client)/client (chez le server) et comme valeur le mot de passe (en gros un server se souvient avec quel client il partage quel mot de passe, et le client se souvient avec quel server il partage quel mot de passe)
  * du coup faudrait une nouvelle méthode `addServer(server,password)` dans la classe client et une méthode `addClient(client,password)`
* faire un 2ème dictionnaire côté serveur qui aura comme clés des instances de client et comme valeur le challenge
* ne pas devoir passer le mot de passe ni challenge à `checkResponse` de la classe server, mais plutôt passer une référence au client, ça serait possible en implémentant les dictionnaires des 2 premiers points

## sources

* <https://hcsw.org/reading/chalresp.txt>
* <https://pynative.com/python-generate-random-string/>
chapitre "Use_The_Secrets_module_to_generate_a_secure_random_string"