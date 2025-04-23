# Summary: Filtering CrdsData with Private Inner Types

**Date:** 2023-10-27

**Context:**
During the implementation of an ingress filter for `agave-snapshot-gossip-client` (using a local fork of `anza-xyz/agave`), we aimed to control which `solana_gossip::crds_data::CrdsData` variants are processed to minimize resource usage. The filtering is implemented via a closure passed to `ClusterInfo::set_ingress_filter`.

**Problem Statement:**
The external filter closure, defined in the client code, cannot explicitly match certain `CrdsData` variants in either an allowlist or a blocklist. This is because the inner types associated with these variants (e.g., the `Version` struct within `CrdsData::Version(Version)`) are private within the `solana-gossip` crate.

Attempting to match these variants results in compile-time privacy errors:

```rust
// Example Allowlist Filter (Fails to compile)
let filter = Arc::new(|data: &CrdsData| {
    matches!(data,
        CrdsData::ContactInfo(_)
        | CrdsData::Version(_) // <-- Compile Error: `crds_data::Version` is private
        | CrdsData::AccountsHashes(_) // <-- Compile Error: `crds_data::AccountsHashes` is private
        | CrdsData::NodeInstance(_) // <-- Compile Error: `crds_data::NodeInstance` is private
        // Similar issues with Legacy* variants
    )
});

// Example Blocklist Filter (Also Fails)
let filter = Arc::new(|data: &CrdsData| {
    !matches!(data,
        CrdsData::Vote(_,_)
        | CrdsData::Version(_) // <-- Compile Error: `crds_data::Version` is private
        // ... other variants ...
    )
});
```

**Current Workaround:**
We are using a blocklist filter implemented with `!matches!`. This filter explicitly blocks variants whose inner types *are* public and which we know are unnecessary (e.g., `Vote`, `LowestSlot`, `EpochSlots`, `DuplicateShred`).

```rust
// Current Filter in src/gossip.rs
let ingress_filter: Arc<dyn Fn(&CrdsData) -> bool + Send + Sync + 'static> =
    Arc::new(|data| {
        !matches!(data,
            // Blocked types (publicly matchable):
            CrdsData::Vote(_, _)
            | CrdsData::LowestSlot(_, _)
            | CrdsData::EpochSlots(_, _)
            | CrdsData::DuplicateShred(_, _)
            | CrdsData::RestartHeaviestFork(_)
            | CrdsData::RestartLastVotedForkSlots(_)
        )
        // Implicitly Allowed: ContactInfo, SnapshotHashes, Version, AccountsHashes, NodeInstance, Legacy*
    });
```
**Trade-off:** This workaround functions but is less precise than desired. It allows types like `Version`, `AccountsHashes`, and `NodeInstance` to pass the external filter (because we can't block them explicitly), meaning they are still processed by the internal `solana-gossip` logic. This is acceptable for now but prevents maximally aggressive filtering if these types were also deemed unnecessary.

**Rejected Alternative (External Discriminant):**
An attempt was made to use `std::mem::discriminant` to build a `HashSet` of variants to block/allow externally. This failed because creating the necessary dummy `CrdsData` instances required the inner types to implement `Default`, which many (like `Vote`) do not.

**Potential Upstream Solution (Improving Filtering API in `solana-gossip`):**
Directly requesting that the inner types (`Version`, `AccountsHashes`, etc.) be made public is unlikely to be accepted by upstream maintainers due to concerns about API surface stability and encapsulation.

A more promising approach for an upstream contribution would be to enhance the filtering mechanism *within* `solana-gossip` itself, allowing external users to specify rules without needing access to private types:

1.  **Accept Discriminants:** Modify `ClusterInfo::set_ingress_filter` (or add a new method) to accept a `HashSet<std::mem::Discriminant<CrdsData>>`. The `solana-gossip` crate could potentially provide helpers to build this set without requiring external `Default` implementations.
2.  **Public `CrdsDataType` Enum:** Introduce a *new, public* enum (e.g., `CrdsDataType`) that mirrors the `CrdsData` variants but *without* any associated data. Modify the filter function signature to accept rules based on this public enum (e.g., `Fn(&CrdsDataType) -> bool` or a `HashSet<CrdsDataType>`).

**Conclusion:**
The current blocklist filter is a functional workaround. For a more precise and robust filtering solution that can accurately target all `CrdsData` variants, engaging with upstream maintainers to improve the filtering API within `solana-gossip` itself is the recommended path forward. The focus should be on enabling external control without exposing internal implementation details. 
