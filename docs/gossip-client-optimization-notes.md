# Summary of Findings for `agave-snapshot-gossip-client` Optimization

**Problem:**
*   The client experiences excessive CPU and memory usage, likely due to processing the full Solana gossip firehose (Ref: [GitHub Issue #53](https://github.com/Blockdaemon/agave-snapshot-gossip-client/issues/53)).
*   The client receives far more data than it sends and processes data irrelevant to its core function of discovering/publishing snapshot hashes.

**Goal:**
*   Reduce resource usage by making the client only handle the absolute minimum necessary gossip traffic.

**Proposed Strategy: Minimal Gossip Participation via Configurable Light Mode**
*   **Push Only Focus:** The client's primary *active* role should remain pushing its *own* snapshot hash information.
*   **Minimal Necessary Ingress Processing:** The client *must* still process *some* ingress data:
    *   `ContactInfo`: To discover peers (potential push targets).
    *   `Pong` messages (if sending Pings): To verify peer reachability before pushing.
    *   Initial entrypoint communication.
*   **Configurable Filtering of Other Ingress:** Implement logic to aggressively filter out and discard other incoming CRDS updates (specifically `CrdsData::Vote` initially, and potentially others like EpochSlots, DuplicateShreds, relayed data) *based on configuration*. This filtering should happen as early as possible upon receipt.
*   **Configurable Disabling of Pull:** Implement logic to *disable* initiating gossip pulls and generating responses to pull requests *based on configuration*.

*(This strategy is formalized in the [Light Gossip Mode Proposal](light-gossip-mode-proposal.md)).*

**Implementation Approach:**
*   **Requires Modifying Core Gossip Code via Forking:** Achieving this level of filtering and behaviour modification requires changing the internal logic of `solana-gossip`.
*   **Recommendation: Fork `anza-xyz/agave` Repository:** Create a fork of the main Agave monorepo. This allows modifying `solana-gossip` (and potentially other crates if needed) while keeping the changes manageable and facilitating potential upstream Pull Requests. Use path dependencies in the client's `Cargo.toml` to point to the local fork during development.
*   **Modify the Forked `solana-gossip` Code:**
    *   Introduce configuration flags/parameters (e.g., `light_mode_enabled: bool`, `filter_ingress_types: HashSet<CrdsDataType>`, `disable_pull_gossip: bool`) passed during `ClusterInfo`/`GossipService` initialization.
    *   In `ClusterInfo::process_gossip_packets` (or similar): Add conditional logic to check the flags and immediately discard unwanted incoming `CrdsValue` types *before* insertion into the `Crds` table or further processing.
    *   In `ClusterInfo::gossip` loop: Add conditional logic to prevent calls related to initiating pull requests (`CrdsGossipPull::new_pull_request`) if configured.
    *   In `ClusterInfo::listen` pathway: Add conditional logic to prevent calls related to generating pull responses (`CrdsGossipPull::generate_pull_responses`) if configured.
    *   (Optional) Add logic to ensure the push mechanism (`CrdsGossipPush::new_push_messages`) primarily pushes self-generated data if configured.

**Benefits:**
*   Should drastically reduce CPU load (less deserialization, signature verification, CRDS updates).
*   Should significantly reduce memory usage (smaller CRDS table).
*   Should reduce ingress bandwidth consumption.

**Scope:**
*   This approach involves managing a fork of the `anza-xyz/agave` repository. Changes are made to the `solana-gossip` crate within that fork. This structure is suitable for developing the feature and potentially contributing it back upstream.
*   The snapshot client itself will enable the appropriate configuration flags in the modified gossip code it depends on.
