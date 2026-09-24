## 2026-09-24 - Duplicate Signer Validation in Wallet Initialization
**Vulnerability:** Initializing multi-sig wallets with duplicate signer addresses allowed creating wallets with reduced signer counts or single-owner configurations where funds become permanently locked because transactions require two distinct signers.
**Learning:** Checking for address zero is not sufficient when initializing arrays of signers; array elements must also be validated for uniqueness to maintain intended m-of-n security invariants.
**Prevention:** Always assert uniqueness using mapping state or nested iterations during array-based identity assignment.
