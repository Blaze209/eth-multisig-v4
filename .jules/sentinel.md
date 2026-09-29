## 2026-03-31 - Uninitialized State Check Flaw via Default Zero Address
**Vulnerability:** `Forwarder.sol` determined initialization status via `parentAddress == address(0)`. Because `init()` did not reject `_parentAddress = address(0)`, calling `init()` with zero address left `parentAddress` as `address(0)`. This allowed subsequent calls to `init()` by any caller, enabling contract takeover.
**Learning:** Using a state variable's uninitialized default value (e.g. `address(0)`) as the initialization flag without validating input against that value creates a takeover vulnerability.
**Prevention:** Always validate initialization parameters against the uninitialized default state, or use an explicit boolean `initialized` flag.
