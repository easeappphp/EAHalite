<?php
require '../vendor/autoload.php';


use ParagonIE\Halite\KeyFactory;

//Crypto Key Storage Path
$crypto_key_storage_path = '/home/username/public_html/EAHalite/examples/keys/';

//Create the Crypto Key Storage Directory, if it doesn't exist!
if (!file_exists($crypto_key_storage_path)) {
	
	mkdir($crypto_key_storage_path, 0755, true);
	
}

clearstatcache();

//Check, if Libsodium is setup correctly
if (ParagonIE\Halite\Halite::isLibsodiumSetupCorrectly() === true) {
	
	//Generate Symmetric Encryption Key
	$symmetric_encryption_key = \ParagonIE\Halite\KeyFactory::generateEncryptionKey();
	//Save the generated Symmetric Encryption key to a file
	\ParagonIE\Halite\KeyFactory::save($symmetric_encryption_key, $crypto_key_storage_path . 'xsalsa20_symmetric_encryption.key');
	
	//Generate Symmetric Authentication Key (Digital Signature)
	$symmetric_authentication_key = \ParagonIE\Halite\KeyFactory::generateAuthenticationKey();
	//Save the generated Symmetric Key Authentication key to a file
	\ParagonIE\Halite\KeyFactory::save($symmetric_authentication_key, $crypto_key_storage_path . 'hmac_sha512_or_sha256_symmetric_authentication.key');
	
	//Generate File related Symmetric Encryption Key
	$file_rel_symmetric_encryption_key = \ParagonIE\Halite\KeyFactory::generateEncryptionKey();
	//Save the generated Symmetric Encryption key to a file
	\ParagonIE\Halite\KeyFactory::save($file_rel_symmetric_encryption_key, $crypto_key_storage_path . 'xsalsa20_file_rel_symmetric_encryption.key');
	
	//Generate File Related Symmetric Authentication Key (Digital Signature)
	$file_rel_symmetric_authentication_key = \ParagonIE\Halite\KeyFactory::generateAuthenticationKey();
	//Save the generated Symmetric Key Authentication key to a file
	\ParagonIE\Halite\KeyFactory::save($file_rel_symmetric_authentication_key, $crypto_key_storage_path . 'hmac_sha512_or_sha256_file_rel_symmetric_authentication.key');
	 
	//Generate Asymmetric Authenticated Encryption Key
	$asymmetric_authenticated_encryption_keypair = \ParagonIE\Halite\KeyFactory::generateEncryptionKeyPair();
	//Save the generated Asymmetric Authenticated Encryption keypair to a file
	\ParagonIE\Halite\KeyFactory::save($asymmetric_authenticated_encryption_keypair, $crypto_key_storage_path . 'curve25519-asymmetric-authenticated-encryption-keypair.key');
		 
	//Generate Asymmetric Anonymous Encryption Key
	$asymmetric_anonymous_encryption_keypair = \ParagonIE\Halite\KeyFactory::generateEncryptionKeyPair();
	//Save the generated Asymmetric Anonymous Encryption keypair to a file
	\ParagonIE\Halite\KeyFactory::save($asymmetric_anonymous_encryption_keypair, $crypto_key_storage_path . 'curve25519_asymmetric_anonymous_encryption_keypair.key');
	
	//Generate Asymmetric Authentication Key (Digital Signature)
	$asymmetric_authentication_keypair = \ParagonIE\Halite\KeyFactory::generateSignatureKeyPair();
	//Save the generated Asymmetric Authentication keypair to a file
	\ParagonIE\Halite\KeyFactory::save($asymmetric_authentication_keypair, $crypto_key_storage_path . 'ed25519_asymmetric_authentication_keypair.key');
	
	//Generate File related Asymmetric Anonymous Encryption Key
	$file_rel_asymmetric_anonymous_encryption_keypair = \ParagonIE\Halite\KeyFactory::generateEncryptionKeyPair();
	//Save the generated Asymmetric Anonymous Encryption keypair to a file
	\ParagonIE\Halite\KeyFactory::save($file_rel_asymmetric_anonymous_encryption_keypair, $crypto_key_storage_path . 'curve25519_file_rel_asymmetric_anonymous_encryption_keypair.key');
	
	//Generate File related Asymmetric Authentication Key (Digital Signature)
	$file_rel_asymmetric_authentication_keypair = \ParagonIE\Halite\KeyFactory::generateSignatureKeyPair();
	//Save the generated Asymmetric Authentication keypair to a file
	\ParagonIE\Halite\KeyFactory::save($file_rel_asymmetric_authentication_keypair, $crypto_key_storage_path . 'ed25519_file_rel_asymmetric_authentication_keypair.key');

	
}




