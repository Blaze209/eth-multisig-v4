# Smart Contract Security Audit Report

VERDICT: VULNERABLE
Confidence: HIGH

## Summary
The `WalletSimple` multisig contract and its derivatives are vulnerable to **Cross-Wallet Signature Replay**. The hashing logic used to authorize multisig transactions does not include the contract's own address (`address(this)`). As a result, a signature generated for one wallet can be replayed on any other wallet that shares the same set of signers and is deployed on the same chain.

## Evidence

### Code Location
`contracts/WalletSimple.sol`: lines 174-176, 226-234, 291-300

### Actual Code Snippet
```solidity
    // sendMultiSig
    bytes32 operationHash = keccak256(
      abi.encode(getNetworkId(), toAddress, value, data, expireTime, sequenceId)
    );

    // sendMultiSigBatch
    bytes32 operationHash = keccak256(
      abi.encode(
        getBatchNetworkId(),
        recipients,
        values,
        expireTime,
        sequenceId
      )
    );

    // sendMultiSigToken
    bytes32 operationHash = keccak256(
      abi.encodePacked(
        getTokenNetworkId(),
        toAddress,
        value,
        tokenContractAddress,
        expireTime,
        sequenceId
      )
    );
```

### Analysis
The `operationHash` in all three multisig execution functions includes a network-specific prefix, the transaction details, and a sequence ID (nonce), but it **lacks the address of the wallet contract itself**. In a typical deployment scenario where users have multiple wallets with the same signers (e.g., across different projects or purposes), an authorized signature for a transaction on one wallet can be intercepted and used to execute an identical transaction on another wallet. While the `sequenceId` provides intra-wallet replay protection, it does not prevent cross-wallet replay if the wallets' nonces happen to align (e.g., both are new or have processed the same number of transactions).

## E2E PoC

### File
`test/CrossWalletReplayPoC.js`

### Run Command
```bash
./node_modules/.bin/hardhat test test/CrossWalletReplayPoC.js --network hardhat
```

### Expected Output
```
  Cross-Wallet Replay Vulnerability PoC
Wallet A address: 0x...
Wallet B address: 0x...
Executing transaction on Wallet A...
Transaction on Wallet A successful.
Attempting to replay the same signature on Wallet B...
VULNERABILITY CONFIRMED: Signature replayed successfully on Wallet B!
    ✔ VULNERABILITY: Cross-Wallet Signature Replay
```

### Actual Output (Executed)
```
  Cross-Wallet Replay Vulnerability PoC
Wallet A address: 0x3ecB95E882D93153219e5004e096DC5bc7BEb02E
Wallet B address: 0x8b84D4AdfB2a097EE88654CA4aBFAD27Ce2daf9c
Executing transaction on Wallet A...
Transaction on Wallet A successful.
Attempting to replay the same signature on Wallet B...
VULNERABILITY CONFIRMED: Signature replayed successfully on Wallet B!
    ✔ VULNERABILITY: Cross-Wallet Signature Replay


  1 passing (357ms)
```

## Why the report is correct
The report identifies a critical violation of EIP-712 and general multisig security best practices. Signatures must always be domain-separated to the specific contract instance they are intended for to prevent replay across different instances of the same contract logic.

## Severity: Critical

- **Likelihood: Medium** - Requires the attacker to find two wallets with identical signers where the nonces are synchronized. This is common when wallets are managed by the same entity and deployed using similar scripts.
- **Impact: Critical** - Allows unauthorized execution of transactions on a victim's wallet, potentially leading to total loss of funds.

## Recommended Action
Report immediately.

## Target Asset
`contracts/WalletSimple.sol` and all derived chain-specific wallet contracts.

## Attack Path
1. Alice has two multisig wallets (Wallet A and Wallet B) with the same three signers. Both wallets are at `sequenceId = 1`.
2. Alice signs a transaction for Wallet A to send 1 ETH to Bob.
3. Bob (the attacker) receives Alice's signature and Alice's transaction is executed on Wallet A.
4. Bob then immediately calls `sendMultiSig` on Wallet B using Alice's same signature and transaction data.
5. Wallet B verifies the signature (which is valid because the hash matches) and executes the transaction, sending Bob another 1 ETH from Wallet B.

## Impact Explanation
This vulnerability breaks the fundamental security guarantee of a multisig wallet: that transactions must be explicitly authorized for *that specific wallet*. An attacker can multiply the effect of a single signature across multiple wallets owned by the same entity.

## Fix Recommendation
Include `address(this)` in the hashing logic for all multisig operations.

```solidity
    bytes32 operationHash = keccak256(
      abi.encode(getNetworkId(), address(this), toAddress, value, data, expireTime, sequenceId)
    );
```

---

## INTENTIONAL DESIGN FLAGS

### Batcher DOS via Single Failing Recipient
- **Status: NOT A VULNERABILITY — Intentional Design**
- **Justification:** The behavior where a single failing recipient reverts the entire batch is explicitly tested in the existing test suite (`test/batcher.js`: `Reverts when a recipient fails`). This indicates that the atomicity of the batch (all succeed or all fail) is a deliberate design choice for this contract.
