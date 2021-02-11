<?php
require '../vendor/autoload.php';

use \EaseAppPHP\EAHalite\EAHalite;
use \EaseAppPHP\EAHalite\Exceptions\EAHaliteException;

use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\Symmetric\Crypto as Symmetric;
use ParagonIE\HiddenString\HiddenString;

//Crypto Key Storage Path
$crypto_key_storage_path = '/home/username/EAHalite/examples/keys/';

try {
	
	//Check, if Libsodium is setup correctly
	if (ParagonIE\Halite\Halite::isLibsodiumSetupCorrectly() === true) {
		
		//Retrieve the previously saved Symmetric Encryption key from the file
		$symmetric_encryption_key = \ParagonIE\Halite\KeyFactory::loadEncryptionKey($crypto_key_storage_path . 'xsalsa20_symmetric_encryption.key');
		
		//Retrieve the previously saved Symmetric Authentication key from the file
		$symmetric_authentication_key = \ParagonIE\Halite\KeyFactory::loadAuthenticationKey($crypto_key_storage_path . 'hmac_sha512_or_sha256_symmetric_authentication.key');
		
		//Retrieve the previously saved File related Symmetric Encryption key from the file
		$file_rel_symmetric_encryption_key = \ParagonIE\Halite\KeyFactory::loadEncryptionKey($crypto_key_storage_path . 'xsalsa20_file_rel_symmetric_encryption.key');
		
		//Retrieve the previously saved File related Symmetric Authentication key from the file
		$file_rel_symmetric_authentication_key = \ParagonIE\Halite\KeyFactory::loadAuthenticationKey($crypto_key_storage_path . 'hmac_sha512_or_sha256_file_rel_symmetric_authentication.key');

		//Retrieve the previously saved Asymmetric Anonymous Encryption key from the file
		$asymmetric_anonymous_encryption_keypair = \ParagonIE\Halite\KeyFactory::loadEncryptionKeyPair($crypto_key_storage_path . 'curve25519_asymmetric_anonymous_encryption_keypair.key');

		$asymmetric_anonymous_encryption_secret_key = $asymmetric_anonymous_encryption_keypair->getSecretKey();
		$asymmetric_anonymous_encryption_public_key = $asymmetric_anonymous_encryption_keypair->getPublicKey();
		
		//Retrieve the previously saved Asymmetric Authentication key from the file
		$asymmetric_authentication_keypair = \ParagonIE\Halite\KeyFactory::loadSignatureKeyPair($crypto_key_storage_path . 'ed25519_asymmetric_authentication_keypair.key');

		$asymmetric_authentication_secret_key = $asymmetric_authentication_keypair->getSecretKey();
		$asymmetric_authentication_public_key = $asymmetric_authentication_keypair->getPublicKey();
		
		//Retrieve the previously saved File related Asymmetric Anonymous Encryption key from the file
		$file_rel_asymmetric_anonymous_encryption_keypair = \ParagonIE\Halite\KeyFactory::loadEncryptionKeyPair($crypto_key_storage_path . 'curve25519_file_rel_asymmetric_anonymous_encryption_keypair.key');

		$file_rel_asymmetric_anonymous_encryption_secret_key = $file_rel_asymmetric_anonymous_encryption_keypair->getSecretKey();
		$file_rel_asymmetric_anonymous_encryption_public_key = $file_rel_asymmetric_anonymous_encryption_keypair->getPublicKey();
		
		//Retrieve the previously saved File Related Asymmetric Authentication key from the file
		$file_rel_asymmetric_authentication_keypair = \ParagonIE\Halite\KeyFactory::loadSignatureKeyPair($crypto_key_storage_path . 'ed25519_file_rel_asymmetric_authentication_keypair.key');

		$file_rel_asymmetric_authentication_secret_key = $file_rel_asymmetric_authentication_keypair->getSecretKey();
		$file_rel_asymmetric_authentication_public_key = $file_rel_asymmetric_authentication_keypair->getPublicKey();
		
	} else {
		
		throw new EAHaliteException("Error with Libsodium Setup, tha is required by Halite! \n");
		
	}

	$eaHalite = new EAHalite($asymmetric_anonymous_encryption_secret_key, $asymmetric_anonymous_encryption_public_key, $asymmetric_authentication_secret_key, $asymmetric_authentication_public_key, $file_rel_asymmetric_anonymous_encryption_secret_key, $file_rel_asymmetric_anonymous_encryption_public_key, $file_rel_asymmetric_authentication_secret_key, $file_rel_asymmetric_authentication_public_key, $symmetric_encryption_key, $symmetric_authentication_key, $file_rel_symmetric_encryption_key, $file_rel_symmetric_authentication_key);


	
	//Create Seal of the Content w.r.t. given File Path
	$eaHalite->fileSeal('sample.txt', 'sample.txt.enc');

	//Create Digital Signature for the given File Path (Encrypted File in this scenario)
	$file_digital_signature = $eaHalite->fileDigitalSignature('sample.txt.enc', 'base64urlsafe');
	echo "file digital signature: \n" . $file_digital_signature . "\n\n";

	//Verify Digital Signature of the given File (Encrypted File in this scenario)
	$file_digital_signature_verification_result = $eaHalite->verifyFileDigitalSignature('sample.txt.enc', $file_digital_signature, 'base64urlsafe');
	echo "file digital signature verification result: \n";
	var_dump($file_digital_signature_verification_result);
	echo "\n\n";

	//Un Seal File w.r.t. the given File Path
	$eaHalite->fileUnSeal('sample.txt.enc', 'sample_decrypted.txt');


	$eaHalite->symmetricFileEncrypt('sample.txt', 'sample.txt.enc');
	$eaHalite->symmetricFileDecrypt('sample.txt.enc', 'sample_decrypted_symmetric.txt');
	//Create Digital Signature for the given File Path (Encrypted File in this scenario, using Symmetric File Encryption)
	$file_digital_signature_for_symmetric_encrypted_content = $eaHalite->fileDigitalSignature('sample.txt.enc', 'base64urlsafe');
	echo "file_digital_signature_for_symmetric_encrypted_content: " . $file_digital_signature_for_symmetric_encrypted_content . "\n\n";
	 
	$symmetric_encrypted_content = $eaHalite->symmetricEncrypt("Sri Rama"); 
	echo "symmetric_encrypted_content: " . $symmetric_encrypted_content . "\n\n";


	$decrypted_plaintext_content = $eaHalite->symmetricDecrypt($symmetric_encrypted_content);
	echo "decrypted_plaintext_content: " . $decrypted_plaintext_content . "\n\n";
	 

	 
	$created_hmac = $eaHalite->symmetricAuthenticationCreateHMAC("Sri Rama"); 
	echo "created_hmac: " . $created_hmac . "\n\n";

	$hmac_verification_result = $eaHalite->symmetricAuthenticationVerifyHMAC("Sri Rama", $created_hmac);
	echo "hmac_verification_result: \n";
	var_dump($hmac_verification_result);
	echo "\n\n";

	
} catch (EAHaliteException $e) {
	
	echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
	
}

?>
