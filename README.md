# One Time Secret - Keep sensitive data out of email and chat logs

## Overview
This is my own take on the already existing https://onetimesecret.com

This application allows users to temporarily store sensitive information and pass it along easily and securely. Each secret has it's own unique url. Upon retrieval, the secret gets deleted from the database immediately. Each secret can thus be retrieved only once. If the recipient can not retrieve the secret when accessing the unique url, someone else might have seen the secret already, therefor the data might be compromised.

## Security concept
The idea behind this application is that the shared inormation is secure per definition upon access because it can be viewed only once. If you can see the secret, you are per definition the first and only one to have accessed this information.

Each record in the database has a TTL (time to live) with a max of 24 hours. This means no sensitive info will linger around if it is not retrieved in a timely fashion. After storing a secret, you can simply send the unique url over an insecure channel like email, chat, whatever.

The information that would be shared through this application is contextless ideally : Do not create a secret containing server address, username and password. Instead, only store a password, sshkey or whatever, without any further context. All non-trivial information like server address and username can be shared outside of Onetimesecret. 

All information in the database is encrypted (AES256) and each entry is salted with a random salt. The application encrypts and decrypts the information based on a predefined encryption key stored in an Environment Variable.

## Usage
The application allows you to store or generate three different kinds of 'secret': Custom, Random String or SSH Keypair.

- Custom Secret any piece of arbitrary text. Can be a self chosen password, an existing private key, a certificate, whatever.
- Random String: generate a random string of X characters, simple (letters and numbers) or complex (+ non alpha characters)
- SSH Keypair: Generate a DSA or RSA keypair with desired bitlength. Private key can be encrypted. Secret contains (encrypted) private key, public key, and public key in ssh format.

A comment and an email address can be added to each secret. Use the comment field to add a short description. When email address is filled out, an email with the secret's unique url is sent to this address. Additionally, this email address needs to be entered when the secret is retrieved.

# Technology
Onetimesecret is written in Ruby and uses the Sinatra framework.  
It relies on environment variables for all of it's configuration. This allows for easy deployment on the container platform of your choice (e.g. Redhat Openshift).  
All information is stored in a Redis database.

