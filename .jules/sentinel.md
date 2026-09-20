## 2025-05-18 - Unvalidated Zero Address in Forwarder Initialization Allows Hijacking
**Vulnerability:** `Forwarder.sol` used `parentAddress == address(0x0)` as its initialization check (`onlyUninitialized`) but lacked zero-address validation (`require(_parentAddress != address(0x0))`) in `init()`.
**Learning:** If a contract uses a state variable (e.g. `parentAddress`) as its `onlyUninitialized` guard instead of an explicit `initialized` boolean, initializing it with `address(0)` leaves the guard true and enables external callers to re-initialize and hijack the contract later.
**Prevention:** Always validate that initial addresses are non-zero (`require(_parentAddress != address(0x0))`) or use an explicit boolean `initialized` flag.
