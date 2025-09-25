# BTC-Backed Identity Vault

A decentralized identity management system built on Stacks that enables users to store and verify credentials anchored to Bitcoin.

## Features

- **Decentralized Profiles**: Users can create profiles to manage their digital identity
- **Credential Storage**: Secure storage of credential hashes with issuer verification
- **Reputation System**: Built-in reputation scoring based on verified credentials
- **Expiration Management**: Automatic handling of time-sensitive credentials
- **Bitcoin Security**: Leverages Bitcoin's security through Stacks integration

## Contract Functions

### Public Functions
- `create-profile()`: Initialize a new user profile
- `add-credential()`: Add a new credential to user's vault
- `verify-credential()`: Admin function to verify credential authenticity

### Read-Only Functions  
- `get-credential()`: Retrieve credential details
- `get-user-profile()`: Get user profile information

## Usage

Deploy the contract and users can begin creating profiles and adding verifiable credentials that are cryptographically secured and anchored to Bitcoin.

## Security

All credentials are stored as hashes, ensuring privacy while maintaining verifiability through the issuer system.