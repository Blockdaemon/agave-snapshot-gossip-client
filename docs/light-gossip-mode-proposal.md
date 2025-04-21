# Proposal: Configurable "Light Gossip Mode" for Non-Consensus Nodes

**1. Problem Statement:**

Nodes participating in the Solana gossip network that are *not* directly involved in consensus (primarily non-voting validators, but also RPC nodes and specialized clients like snapshot providers) currently incur significant CPU, memory, and bandwidth overhead. They process the full CRDS gossip stream, including data like `CrdsData::Vote`, which is essential for voting validators but largely constitutes noise for non-consensus nodes. This overhead hinders leaner infrastructure deployments and directly contributes to existing maintainer concerns regarding the excessive network impact and resource consumption of non-voting validators. (See [Optimization Notes](gossip-client-optimization-notes.md) for further background on the resource usage issues.)

**2. Proposed Solution:**

Introduce a new, **optional and configurable "Light Gossip Mode"** within the core `solana-gossip` crate (`ClusterInfo` / `GossipService`). This mode is designed to be immediately beneficial for non-voting validators upon activation. When enabled via configuration, it would modify behavior to:

*   **Selectively Filter Ingress:** Immediately discard `CrdsData::Vote` messages (and potentially other configurable types) upon receipt, preventing storage in the local `Crds` table and associated processing/signature verification overhead.
*   **Reduce/Disable Pull Participation (Optional):** Allow configuration to optionally disable initiating outgoing pulls or responding to incoming pulls, further reducing load.
*   **(Future Scope) Limit Push Scope:** While the initial focus is ingress filtering, the framework could allow future configuration to limit data pushed by these nodes.

**3. Benefits:**

*   **Reduced Non-Voting Validator Load:** Directly lowers CPU, memory, and bandwidth consumption for non-voting validators by filtering irrelevant consensus traffic (`CrdsData::Vote`), addressing a key maintainer concern *with this initial implementation*.
*   **Improved Ecosystem Efficiency:** Enables leaner deployment of other non-consensus nodes (RPCs, monitoring, specific clients) using the same mechanism.
*   **Maintained Core Stability:** Designed as an *opt-in* mode, leaving the default behavior and performance for voting validators completely unchanged and unaffected.

**4. Implementation Sketch:**

*   Introduce configuration flags/parameters passed during `ClusterInfo`/`GossipService` initialization (e.g., `enable_light_gossip_mode: bool`, potentially `filter_ingress_types: Vec<CrdsDataType>`).
*   Add conditional logic within key processing pathways (e.g., `ClusterInfo::process_gossip_packets`, `CrdsGossip` pull logic) to filter data or bypass steps based on the configured mode.
*   Ensure comprehensive testing verifies the light mode's functionality (especially for the non-voting validator use case) and the non-regression of the default validator mode.

**5. Next Steps:**

Seeking feedback on the viability and design of this opt-in mode. We believe this offers a practical solution to reduce the resource footprint of non-voting validators and other non-consensus nodes, directly addressing expressed concerns without impacting core validator operation. We are prepared to develop this feature within a fork and submit a PR for consideration.
