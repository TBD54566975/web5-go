# web5 

## Usage

```shell
➜ web5 -h
Usage: web5 <command>

Web5 - A decentralized web platform that puts you in control of your
data and identity.

Flags:
  -h, --help    Show context-sensitive help.

Commands:
  jwt sign <claims> <portable-did>
    Sign a JWT.

  jwt decode <jwt>
    Decode a JWT.

  jwt verify <jwt>
    Verify a JWT.

  did resolve <uri>
    Resolve a DID.

  did create jwk
    Create a did:jwk.

  did create web <domain>
    Create a did:web.

  vc create <credential-subject-id>
    Create a VC.

  vc sign <vc> <portable-did>
    Sign a VC.

  vc jwt verify <jwt>
    Verify a VC-JWT.

  vc jwt decode <jwt>
    Decode a VC-JWT.

  did create dht
    Create did:dht's using the default gateway.
    
Run "web5 <command> --help" for more information on a command.
```
