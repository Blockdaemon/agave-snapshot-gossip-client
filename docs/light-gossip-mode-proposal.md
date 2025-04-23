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

*   Introduce an optional parameter during `ClusterInfo`/`GossipService` initialization to accept a filtering closure:
    ```rust
    incoming_filter: Option<Arc<dyn Fn(&CrdsData) -> bool + Send + Sync + 'static>>
    ```
*   Modify key processing pathways (e.g., where incoming `CrdsValue`s are handled before insertion or heavy processing) to check if the `incoming_filter` is `Some`.
*   If a filter exists, execute it with the incoming `CrdsData`. If the closure returns `false`, discard the `CrdsValue` immediately.
*   If the filter is `None` or returns `true`, proceed with the standard processing logic.
*   (Optional) Similar optional closures or flags could be added to control pull request generation/response behavior if needed, passed during initialization.
*   Ensure comprehensive testing verifies the light mode's functionality (especially for the non-voting validator use case) and the non-regression of the default validator mode.

**5. Next Steps:**

Seeking feedback on the viability and design of this opt-in mode. We believe this offers a practical solution to reduce the resource footprint of non-voting validators and other non-consensus nodes, directly addressing expressed concerns without impacting core validator operation. We are prepared to develop this feature within a fork and submit a PR for consideration.
