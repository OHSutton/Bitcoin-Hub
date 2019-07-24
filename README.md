# bitcoin-pytools
An ongoing project that will contain all necessary tools to interact with the bitcoin network.  This project is purely intended to extend my knowledge about Bitcoin and cryptocurrency, as well as provide a reference implementation for each of the tools it contains. 

## Tools it contains
This is a work in progress, so here is a rough outline of the final project
- A Bitcoin private key/public key/address generator
	- This is almost complete, I just need to add support for BIP-38 (Passphrase encryption), P2SH and Multisignature addresses.  I will revisit these after I develop the Wallet
	- I also need to fix up the documentation
- Bitcoin Wallet (TODO)
	- Need to implement and clean up the child key derivation functons for the HD Wallet
	- Need to implement my own functions for PBKDF2 key stretching and base58 encoding. 
	- also have to do transactions
- Bitcoin Miner (TODO)
- Transaction Explorer (Not sure about this one since the user may have to run a full node to get this functionality) (TODO)

## Features I may include
- Coloured coins support
- Segwit support

## Frontend Design
It will probably take me a while to get to here
