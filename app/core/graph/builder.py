import logging
import networkx as nx
import pandas as pd
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple

logger = logging.getLogger(__name__)

def build_threat_graph(db, start_time, end_time) -> Dict[str, Any]:
    """Build a graph representation of entities and their relationships"""
    logger.info("Building threat graph")
    
    # Get logs
    auth_logs = list(db.auth_logs.find({"timestamp": {"$gte": start_time, "$lte": end_time}}))
    network_logs = list(db.network_logs.find({"timestamp": {"$gte": start_time, "$lte": end_time}}))
    
    if not auth_logs and not network_logs:
        logger.info("No logs found for building threat graph")
        return {
            "node_count": 0,
            "edge_count": 0,
            "top_central_entities": [],
            "graph": None
        }
    
    # Create graph
    G = nx.DiGraph()
    
    # Add nodes and edges from authentication logs
    if auth_logs:
        auth_df = pd.DataFrame(auth_logs)
        
        # Add user nodes
        for user in auth_df['username'].unique():
            G.add_node(user, type='USER')
        
        # Add IP nodes
        for ip in auth_df['src_ip'].unique():
            G.add_node(ip, type='IP')
        
        # Add host nodes
        for host in auth_df['dest_host'].unique():
            G.add_node(host, type='HOST')
        
        # Add edges from IP to users (authentication attempts)
        for _, row in auth_df.iterrows():
            edge_data = {
                'timestamp': row['timestamp'],
                'status': row['status'],
                'auth_method': row['auth_method'],
                'type': 'AUTH'
            }
            G.add_edge(row['src_ip'], row['username'], **edge_data)
        
        # Add edges from users to hosts (access)
        for _, row in auth_df.iterrows():
            edge_data = {
                'timestamp': row['timestamp'],
                'status': row['status'],
                'auth_method': row['auth_method'],
                'type': 'ACCESS'
            }
            G.add_edge(row['username'], row['dest_host'], **edge_data)
    
    # Add nodes and edges from network logs
    if network_logs:
        network_df = pd.DataFrame(network_logs)
        
        # Add IP nodes
        for ip in pd.concat([network_df['src_ip'], network_df['dest_ip']]).unique():
            if ip not in G:
                G.add_node(ip, type='IP')
        
        # Add edges between IPs (network communication)
        for _, row in network_df.iterrows():
            edge_data = {
                'timestamp': row['timestamp'],
                'src_port': int(row['src_port']),
                'dest_port': int(row['dest_port']),
                'protocol': row['protocol'],
                'action': row['action'],
                'bytes_sent': int(row['bytes_sent']),
                'bytes_received': int(row['bytes_received']),
                'type': 'NETWORK'
            }
            if 'label' in row and row['label'] == 'attack':
                edge_data['is_attack'] = True
            
            G.add_edge(row['src_ip'], row['dest_ip'], **edge_data)
    
    # Enrich nodes with entity information
    # Add asset information
    assets = {asset['host']: asset for asset in db.assets.find({})}
    for host, asset in assets.items():
        if host in G:
            G.nodes[host]['criticality'] = asset['criticality']
            G.nodes[host]['owner'] = asset['owner']
            G.nodes[host]['ip_address'] = asset['ip_address']
    
    # Add threat intelligence information
    threat_intel = {item['indicator']: item for item in db.threat_intel.find({"type": "IP"})}
    for ip, intel in threat_intel.items():
        if ip in G:
            G.nodes[ip]['threat_level'] = intel['threat_level']
            G.nodes[ip]['threat_source'] = intel['source']
            G.nodes[ip]['first_seen'] = intel['first_seen']
            G.nodes[ip]['last_seen'] = intel['last_seen']
    
    # Calculate centrality measures
    try:
        # Degree centrality
        degree_centrality = nx.degree_centrality(G)
        # Betweenness centrality (with limit for large graphs)
        if len(G) < 1000:
            betweenness_centrality = nx.betweenness_centrality(G)
        else:
            betweenness_centrality = {}
            
        # Add centrality measures to nodes
        for node in G.nodes():
            G.nodes[node]['degree_centrality'] = degree_centrality.get(node, 0)
            G.nodes[node]['betweenness_centrality'] = betweenness_centrality.get(node, 0)
            
        # Get top central entities
        top_central_entities = []
        sorted_by_degree = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)
        
        for node, score in sorted_by_degree[:10]:
            node_type = G.nodes[node].get('type', 'UNKNOWN')
            centrality_data = {
                'entity_id': node,
                'entity_type': node_type,
                'degree_centrality': score,
                'betweenness_centrality': betweenness_centrality.get(node, 0),
            }
            
            # Add extra info based on entity type
            if node_type == 'HOST' and 'criticality' in G.nodes[node]:
                centrality_data['criticality'] = G.nodes[node]['criticality']
                centrality_data['owner'] = G.nodes[node].get('owner', 'Unknown')
            elif node_type == 'IP' and 'threat_level' in G.nodes[node]:
                centrality_data['threat_level'] = G.nodes[node]['threat_level']
                
            top_central_entities.append(centrality_data)
    
    except Exception as e:
        logger.error(f"Error calculating centrality: {str(e)}")
        top_central_entities = []
    
    # Store the graph for later use
    try:
        # Convert the graph to a serializable format
        serialized_graph = nx.node_link_data(G)
        
        # Save the serialized graph
        db.graph_data.update_one(
            {"timestamp": {"$gte": start_time}},
            {
                "$set": {
                    "timestamp": end_time,
                    "graph": serialized_graph,
                    "start_time": start_time,
                    "end_time": end_time
                }
            },
            upsert=True
        )
    except Exception as e:
        logger.error(f"Error saving graph: {str(e)}")
        
    # Return summary
    return {
        "node_count": len(G.nodes()),
        "edge_count": len(G.edges()),
        "top_central_entities": top_central_entities,
        "graph": G  # Return the actual graph object
    }

def get_latest_graph(db):
    """Get the latest graph from the database"""
    try:
        # Get the latest graph data
        graph_data = db.graph_data.find_one({}, sort=[("timestamp", -1)])
        
        if not graph_data:
            logger.warning("No graph data found in the database")
            return None
        
        # Deserialize the graph
        G = nx.node_link_graph(graph_data["graph"])
        
        return {
            "graph": G,
            "start_time": graph_data["start_time"],
            "end_time": graph_data["end_time"],
            "timestamp": graph_data["timestamp"]
        }
        
    except Exception as e:
        logger.error(f"Error retrieving graph: {str(e)}")
        return None

def find_attack_paths(G, source, target, max_paths=5):
    """Find potential attack paths between source and target entities"""
    try:
        # Check if source and target exist in the graph
        if source not in G or target not in G:
            return []
        
        # Find all simple paths between source and target
        all_paths = list(nx.all_simple_paths(G, source, target, cutoff=6))
        
        # Sort paths by length (shortest first)
        all_paths.sort(key=len)
        
        # Format paths for response
        formatted_paths = []
        for i, path in enumerate(all_paths[:max_paths]):
            path_edges = []
            
            # Get edge details for this path
            for j in range(len(path) - 1):
                src = path[j]
                dst = path[j+1]
                
                edge_data = G.get_edge_data(src, dst)
                
                # Format edge for response
                edge = {
                    "source": src,
                    "source_type": G.nodes[src].get("type", "UNKNOWN"),
                    "target": dst,
                    "target_type": G.nodes[dst].get("type", "UNKNOWN"),
                    "relationship": edge_data.get("type", "UNKNOWN"),
                }
                
                # Add additional edge metadata
                if "timestamp" in edge_data:
                    edge["timestamp"] = edge_data["timestamp"]
                if "status" in edge_data:
                    edge["status"] = edge_data["status"]
                if "is_attack" in edge_data and edge_data["is_attack"]:
                    edge["is_attack"] = True
                
                path_edges.append(edge)
                
            formatted_path = {
                "path_id": i + 1,
                "path_length": len(path) - 1,  # Number of edges
                "nodes": path,
                "edges": path_edges
            }
            
            formatted_paths.append(formatted_path)
            
        return formatted_paths
        
    except Exception as e:
        logger.error(f"Error finding attack paths: {str(e)}")
        return []

def get_entity_neighbors(G, entity_id, entity_type=None):
    """Get neighboring entities in the threat graph"""
    try:
        if entity_id not in G:
            return []
        
        # Get all neighbors (both in and out)
        neighbors = list(G.successors(entity_id)) + list(G.predecessors(entity_id))
        neighbors = list(set(neighbors))  # Remove duplicates
        
        # Filter by entity type if provided
        if entity_type:
            neighbors = [n for n in neighbors if G.nodes[n].get("type") == entity_type]
        
        # Format neighbor data
        result = []
        for neighbor in neighbors:
            neighbor_data = {
                "entity_id": neighbor,
                "entity_type": G.nodes[neighbor].get("type", "UNKNOWN"),
                "relationships": []
            }
            
            # Get relationships from entity to neighbor
            if G.has_edge(entity_id, neighbor):
                edge_data = G.get_edge_data(entity_id, neighbor)
                rel = {
                    "direction": "outgoing",
                    "type": edge_data.get("type", "UNKNOWN")
                }
                # Add additional relationship data
                if "timestamp" in edge_data:
                    rel["timestamp"] = edge_data["timestamp"]
                if "status" in edge_data:
                    rel["status"] = edge_data["status"]
                if "is_attack" in edge_data and edge_data["is_attack"]:
                    rel["is_attack"] = True
                    
                neighbor_data["relationships"].append(rel)
            
            # Get relationships from neighbor to entity
            if G.has_edge(neighbor, entity_id):
                edge_data = G.get_edge_data(neighbor, entity_id)
                rel = {
                    "direction": "incoming",
                    "type": edge_data.get("type", "UNKNOWN")
                }
                # Add additional relationship data
                if "timestamp" in edge_data:
                    rel["timestamp"] = edge_data["timestamp"]
                if "status" in edge_data:
                    rel["status"] = edge_data["status"]
                if "is_attack" in edge_data and edge_data["is_attack"]:
                    rel["is_attack"] = True
                    
                neighbor_data["relationships"].append(rel)
            
            # Add node attributes
            for key, value in G.nodes[neighbor].items():
                if key != "type":
                    neighbor_data[key] = value
            
            result.append(neighbor_data)
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting entity neighbors: {str(e)}")
        return []
