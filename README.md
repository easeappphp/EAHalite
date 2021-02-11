# EAHalite
> A very simple and safe PHP library that provides wrapper methods to handle encryption, decryption along with authentication in both symmetric & asymmetric modes for both text content and files appropriately. This library is based upon Halite library from Paragonie Initiative Enterprises.

## Secure Key Storage
> The keys are to be stored outside web root of the application server.
> Alternatively, they can be stored in Key Management Systems like VaultProject (https://www.vaultproject.io/) or Key Management Services that are offered by AWS, Microsoft Azure, Google Cloud Platform etc..., wherein, some custom development is probably to be made in the scope of saving the generated key from halite and in terms of loading the keys from Key Management System/Key Management Service.

## Security Guideline
> Do re-generate Security keys using the examples/key-generation.php file, to avoid using the pre-generated ones that are provided in examples folder.

## To Do
> Key Lifecycle Management processes are in the planning, even though there is no specific deadline for this thought process.

## Contributors
> - Pradeep Ganapathy
> - Krishnaveni Nimmala

## License
This software is distributed under the [MIT](https://opensource.org/licenses/MIT) license. Please read [LICENSE](https://github.com/easeappphp/PDOLight/blob/main/LICENSE) for information on the software availability and distribution.
