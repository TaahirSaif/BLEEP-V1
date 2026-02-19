use std::collections::HashMap;
use std::net::SocketAddr;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn random() -> Self {
        use rand::Rng;
        let id: u64 = rand::thread_rng().gen();
        Self(id.to_string())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct Kademlia {
    nodes: HashMap<NodeId, SocketAddr>,
}

impl Kademlia {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, id: NodeId, addr: SocketAddr) {
        self.nodes.insert(id, addr);
    }

    pub fn find_node(&self, id: &NodeId) -> Option<&SocketAddr> {
        self.nodes.get(id)
    }

    /// Store a peer in the DHT (wrapper for add_node)
    pub fn store(&mut self, peer_id: &str, peer_address: &str) {
        let node_id = NodeId::new(peer_id.to_string());
        // For now, we'll use a default socket address since we only have the address string
        if let Ok(addr) = peer_address.parse::<SocketAddr>() {
            self.add_node(node_id, addr);
        }
        log::debug!("DHT stored peer {}", peer_id);
    }

    /// Lookup a peer in the DHT (wrapper for find_node)
    pub fn lookup(&self, peer_id: &str) -> Option<String> {
        let node_id = NodeId::new(peer_id.to_string());
        self.find_node(&node_id).map(|addr| addr.to_string())
    }
}
