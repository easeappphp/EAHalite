<?php

declare(strict_types=1);

namespace EaseAppPHP\EAHalite;

use EaseAppPHP\EAHalite\Exceptions\EAHaliteException;

/*
* Name: EAHalite
*
* Author: Raghuveer Dendukuri
*
* Author: Pradeep Ganapathy <bu.pradeep@gmail.com>
*
* Version: 1.0.0
*
* Description: A very simple and safe PHP library that provides wrapper methods to handle encryption, decryption along with authentication in both symmetric & asymmetric modes for 
* both text content and files appropriately. This library is based upon Halite library from Paragonie Initiative Enterprises.
*
* License: MIT
*
* @copyright 2021 easeappphp
*/

class EAHalite {
	
	private $asymmetric_anonymous_encryption_secret_key;
	private $asymmetric_anonymous_encryption_public_key;
	private $asymmetric_authentication_secret_key;
	private $asymmetric_authentication_public_key;
	private $file_rel_asymmetric_anonymous_encryption_secret_key;
    private	$file_rel_asymmetric_anonymous_encryption_public_key;
	private $file_rel_asymmetric_authentication_secret_key;
	private $file_rel_asymmetric_authentication_public_key;
	private $symmetric_encryption_key;
	private $symmetric_authentication_key;
	private $file_rel_symmetric_encryption_key;
	private $file_rel_symmetric_authentication_key;
	
	public function __construct($asymmetric_anonymous_encryption_secret_key, $asymmetric_anonymous_encryption_public_key, $asymmetric_authentication_secret_key, $asymmetric_authentication_public_key, $file_rel_asymmetric_anonymous_encryption_secret_key, $file_rel_asymmetric_anonymous_encryption_public_key, $file_rel_asymmetric_authentication_secret_key, $file_rel_asymmetric_authentication_public_key, $symmetric_encryption_key, $symmetric_authentication_key, $file_rel_symmetric_encryption_key, $file_rel_symmetric_authentication_key){	

		$this->asymmetric_anonymous_encryption_secret_key = $asymmetric_anonymous_encryption_secret_key;
		$this->asymmetric_anonymous_encryption_public_key = $asymmetric_anonymous_encryption_public_key;
		$this->asymmetric_authentication_secret_key = $asymmetric_authentication_secret_key;
		$this->asymmetric_authentication_public_key = $asymmetric_authentication_public_key;
		$this->file_rel_asymmetric_anonymous_encryption_secret_key = $file_rel_asymmetric_anonymous_encryption_secret_key;
		$this->file_rel_asymmetric_anonymous_encryption_public_key = $file_rel_asymmetric_anonymous_encryption_public_key;
		$this->file_rel_asymmetric_authentication_secret_key = $file_rel_asymmetric_authentication_secret_key;
		$this->file_rel_asymmetric_authentication_public_key = $file_rel_asymmetric_authentication_public_key;
		$this->symmetric_encryption_key = $symmetric_encryption_key;
		$this->symmetric_authentication_key = $symmetric_authentication_key;
		$this->file_rel_symmetric_encryption_key = $file_rel_symmetric_encryption_key;
		$this->file_rel_symmetric_authentication_key = $file_rel_symmetric_authentication_key;
		   
    }
	
	/*
	 * Validate Digital Signature
	 * @param string/array/int $actualData 
	 * @param string $signatureData   
	 *	 
	 */
	public function validateDigitalSignature($actualData, $signatureData)
	{
		try {            
		
			$dataToBeverified = serialize($actualData);
		
			//Verify a Message
			$verificationResult = \ParagonIE\Halite\Asymmetric\Crypto::verify(
				$dataToBeverified,
				$this->asymmetric_authentication_public_key,
				$signatureData
			);
			
			if ($verificationResult === true) {
				
				return true;
				
			} else {
				
				return false;
				
			}
			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
	}
	
	/*
	 * Create Digital Signature
	 * @param string/array/int $dataToBeDigitalSigned
	 *
	 */
	public function createDigitalSignature($dataToBeDigitalSigned)
	{        
		try {            
			
			if(($dataToBeDigitalSigned == "") || (is_null($dataToBeDigitalSigned))) {	
		
				$signature = null;
				
			} else {	
			
				$dataToBeDigitalSigned = serialize($dataToBeDigitalSigned);
				
				$signature = \ParagonIE\Halite\Asymmetric\Crypto::sign(
					$dataToBeDigitalSigned,
					$this->asymmetric_authentication_secret_key
				);
				
				$signature = (string)$signature;
				
			}
			
			return $signature;
			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		

	}
	
	/*
	 * Validate DOC C Hash or Doc Crypto Hash
	 * @param string/array/int $actualData
	 * @param string $docCHashData    
	 */
	public function validateDOCChash($actualData, $docCHashData)
	{
		try {            

			$dataToBeverified = serialize($actualData);
		
			//Verify a Message
			$verificationResult = \ParagonIE\Halite\Asymmetric\Crypto::verify(
				$dataToBeverified,
				$this->asymmetric_authentication_public_key,
				$docCHashData
			);
			
			if ($verificationResult === true) {
				
				return true;
				
			} else {
				
				return false;
				
			}
			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
	}
	
	/*
	 * Create Encrypted Version using Asymmetric Anonymous Encryption approach, for given content
	 * @param string/array/int $dataToBeSealed   
	 */
	public function seal($dataToBeSealed)
	{        
		try {
			
			if(($dataToBeSealed == "") || (is_null($dataToBeSealed))) {	
		
				$sealedData = null;
				
			} else {
				
				//Add a Prefix to Content, so even Single Digit/Character can still be sealed, with sufficient entropy
				$dataToBeSealed = "prx".$dataToBeSealed;
				
				$sealedData = \ParagonIE\Halite\Asymmetric\Crypto::seal(
					new \ParagonIE\Halite\HiddenString(
						$dataToBeSealed
					),
					$this->asymmetric_anonymous_encryption_public_key
				);
				
				$sealedData = (string)$sealedData;
				
				
			}
				
			return $sealedData;

			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
	}
	
	/*
	 * Create Decrypted Version using Asymmetric Anonymous Encryption approach, for given content
	 * @param string/array/int $dataToBeUnSealed   
	 */
	public function unSeal($dataToBeUnSealed)
	{        
		try {            
			
			if(($dataToBeUnSealed == "") || (is_null($dataToBeUnSealed))) {	
		
				$unSealedData = null;
				
			} else {	
			
				$unSealedData = \ParagonIE\Halite\Asymmetric\Crypto::unseal(
					$dataToBeUnSealed,
					$this->asymmetric_anonymous_encryption_secret_key
				);
				
				//Remove the Prefix that is added to the Content, in seal operation, to support even Single Digit/Character inputs, with sufficient entropy
				$unSealedData = substr($unSealedData->getString(),3);
				
				$unSealedData = (string)$unSealedData;
				
			}
			
			return $unSealedData;
			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
	}
	
	/*
	 * Create Encrypted Version of the content for the given File
	 *
	 * @param string/resource $inputFileNameWithPath   
	 * @param string/resource $outputFileNameWithPath 
	 *
	 */
	public function fileSeal($inputFileNameWithPath, $outputFileNameWithPath)
	{        
		try {            

			\ParagonIE\Halite\File::seal($inputFileNameWithPath, $outputFileNameWithPath, $this->file_rel_asymmetric_anonymous_encryption_public_key);
			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
		
	}
	
	/*
	 * Create Decrypted Version of the content for the given File
	 *
	 * @param string/resource $inputFileNameWithPath   
	 * @param string/resource $outputFileNameWithPath 
	 *
	 */
	public function fileUnSeal($inputFileNameWithPath, $outputFileNameWithPath)
	{        
		try {            

			\ParagonIE\Halite\File::unseal($inputFileNameWithPath, $outputFileNameWithPath, $this->file_rel_asymmetric_anonymous_encryption_secret_key);
			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
		
	}
	
	/*
	 * Create Digital Signature of the given File
	 *
	 * @param string/resource $inputFileNameWithPath   
	 * @param string $encoding, Default Value = 'base64urlsafe'
	 *
	 */
	public function fileDigitalSignature($inputFileNameWithPath, $encoding)
	{        
		try {            

			$createdFileRelDigitalSignature = \ParagonIE\Halite\File::sign($inputFileNameWithPath, $this->file_rel_asymmetric_authentication_secret_key, $encoding);
		
			return $createdFileRelDigitalSignature;
			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
		
	}
	
	/*
	 * Verify Digital Signature of the given File
	 *
	 * @param string/resource $inputFileNameWithPath   
	 * @param string $signatureString 
	 * @param string $encoding, Default Value = 'base64urlsafe'
	 *
	 */
	public function verifyFileDigitalSignature($inputFileNameWithPath, $signatureString, $encoding)
	{        
		try {            

			$fileRelDigitalSignatureVerificationResult = \ParagonIE\Halite\File::verify($inputFileNameWithPath, $this->file_rel_asymmetric_authentication_public_key, $signatureString, $encoding);
		
			return $fileRelDigitalSignatureVerificationResult;
			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
	}
	
	/*
	 * Create Encrypted Version of the content for the given File
	 *
	 * @param string/resource $inputFileNameWithPath   
	 * @param string/resource $outputFileNameWithPath 
	 *
	 */
	public function symmetricFileEncrypt($inputFileNameWithPath, $outputFileNameWithPath)
	{        
		try {            

			\ParagonIE\Halite\File::encrypt($inputFileNameWithPath, $outputFileNameWithPath, $this->file_rel_symmetric_encryption_key);
			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
		
	}
	
	/*
	 * Create Decrypted Version of the content for the given File
	 *
	 * @param string/resource $inputFileNameWithPath   
	 * @param string/resource $outputFileNameWithPath 
	 *
	 */
	public function symmetricFileDecrypt($inputFileNameWithPath, $outputFileNameWithPath)
	{        
		try {            

			\ParagonIE\Halite\File::decrypt($inputFileNameWithPath, $outputFileNameWithPath, $this->file_rel_symmetric_encryption_key);
			
		} catch (EAHaliteException $e){
			
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
	}
	
	/*
	 * Create Encrypted Version using Symmetric Encryption approach, for the given content
	 * @param string $dataToBeEncrypted   
	 */
	public function symmetricEncrypt($dataToBeEncrypted)
	{        
		try {            

			$cipherText = \ParagonIE\Halite\Symmetric\Crypto::encrypt(
				new \ParagonIE\Halite\HiddenString(
					$dataToBeEncrypted
				),
				$this->symmetric_encryption_key
			);

			return (string)$cipherText;
			
		} catch (EAHaliteException $e){
				
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		

	}
	
	/*
	 * Create Decrypted Version using Symmetric Encryption approach, for the given content
	 * @param string $dataToBeDecrypted   
	 */
	public function symmetricDecrypt($dataToBeDecrypted)
	{        
		try {            

			$decryptedPlainText = \ParagonIE\Halite\Symmetric\Crypto::decrypt(
				$dataToBeDecrypted,
				$this->symmetric_encryption_key
			);

			return (string)$decryptedPlainText;
			
		} catch (EAHaliteException $e){
				
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		

	}

	/*
	 * Create HMAC for the given content
	 * @param string $HMACToBeCreatedOnData
	 */
	public function symmetricAuthenticationCreateHMAC($HMACToBeCreatedOnData)
	{        
		try {            

			$createdHMAC = \ParagonIE\Halite\Symmetric\Crypto::authenticate(
				$HMACToBeCreatedOnData,
				$this->symmetric_authentication_key
			);

			return (string)$createdHMAC;
			
		} catch (EAHaliteException $e){
				
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		

	}
	
	/*
	 * Verify HMAC for the given content
	 *
	 * @param string/resource $inputFileNameWithPath   
	 * @param string $HMACToBeVerifiedOnData
	 * @param string $receivedHMAC
	 *
	 */
	public function symmetricAuthenticationVerifyHMAC($HMACToBeVerifiedOnData, $receivedHMAC)
	{        
		try {            

			$contentRelHMACVerificationResult = \ParagonIE\Halite\Symmetric\Crypto::verify(
				$HMACToBeVerifiedOnData,
				$this->symmetric_authentication_key,
				$receivedHMAC
			);
			
			return $contentRelHMACVerificationResult;
			
		} catch (EAHaliteException $e){
				
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
	}
	
	/*
	 * Wipe Security Keys
	 *
	 */
	public function wipeSecurityKeys()
	{        
		try {            

			unset($GLOBALS['asymmetric_anonymous_encryption_secret_key']);
			unset($GLOBALS['asymmetric_anonymous_encryption_public_key']);
			unset($GLOBALS['asymmetric_authentication_secret_key']);
			unset($GLOBALS['asymmetric_authentication_public_key']);
			unset($GLOBALS['file_rel_asymmetric_anonymous_encryption_secret_key']);
			unset($GLOBALS['file_rel_asymmetric_anonymous_encryption_public_key']);
			unset($GLOBALS['file_rel_asymmetric_authentication_secret_key']);
			unset($GLOBALS['file_rel_asymmetric_authentication_public_key']);		
			unset($GLOBALS['symmetric_encryption_key']);
			unset($GLOBALS['symmetric_authentication_key']);
			unset($GLOBALS['file_rel_symmetric_encryption_key']);
			unset($GLOBALS['file_rel_symmetric_authentication_key']);
			unset($GLOBALS['asymmetric_anonymous_encryption_keypair']);
			unset($GLOBALS['asymmetric_authentication_keypair']);
			unset($GLOBALS['file_rel_asymmetric_anonymous_encryption_keypair']);
			unset($GLOBALS['file_rel_asymmetric_authentication_keypair']);
					
		} catch (EAHaliteException $e){
				
			echo "\n EAHaliteException - ", $e->getMessage(), (int)$e->getCode();
			
		}
		
	}
	
}