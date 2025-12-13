import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from app.database.models import EntityType

logger = logging.getLogger(__name__)

def calculate_entity_risk_scores(db, entity_type: EntityType) -> List[Dict[str, Any]]:
    """Calculate risk scores for entities based on their behavior"""
    logger.info(f"Calculating risk scores for {entity_type} entities")
    
    # Time window for analysis
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)  # Use 7 days of data
    
    if entity_type == EntityType.USER:
        return calculate_user_risk_scores(db, start_time, end_time)
    elif entity_type == EntityType.IP:
        return calculate_ip_risk_scores(db, start_time, end_time)
    elif entity_type == EntityType.HOST:
        return calculate_host_risk_scores(db, start_time, end_time)
    else:
        raise ValueError(f"Unsupported entity type: {entity_type}")

def calculate_user_risk_scores(db, start_time, end_time) -> List[Dict[str, Any]]:
    """Calculate risk scores for user entities"""
    # Get authentication logs
    auth_logs = list(db.auth_logs.find({"timestamp": {"$gte": start_time, "$lte": end_time}}))
    
    if not auth_logs:
        logger.info("No authentication logs found for risk scoring")
        return []
    
    # Convert to DataFrame
    df = pd.DataFrame(auth_logs)
    
    # Get all users
    users = df['username'].unique()
    
    # Risk factors and scores
    risk_scores = []
    
    for user in users:
        user_df = df[df['username'] == user]
        
        # Calculate risk factors
        risk_factors = []
        risk_score = 0.0
        
        # Factor 1: Failed login attempts
        failed_attempts = user_df[user_df['status'] == 'FAILURE'].shape[0]
        if failed_attempts > 0:
            factor_score = min(failed_attempts * 1.0, 3.0)
            risk_factors.append({
                "factor": "Failed Login Attempts",
                "score": factor_score,
                "details": f"{failed_attempts} failed login attempts"
            })
            risk_score += factor_score
        
        # Factor 2: Login attempts outside business hours (approximation)
        hour_of_day = pd.to_datetime(user_df['timestamp']).dt.hour
        non_business_hours = ((hour_of_day < 8) | (hour_of_day > 18)).sum()
        if non_business_hours > 0:
            factor_score = min(non_business_hours * 0.5, 2.0)
            risk_factors.append({
                "factor": "After-Hours Activity",
                "score": factor_score,
                "details": f"{non_business_hours} login attempts outside business hours"
            })
            risk_score += factor_score
        
        # Factor 3: Number of distinct IPs
        distinct_ips = user_df['src_ip'].nunique()
        if distinct_ips > 2:
            factor_score = min((distinct_ips - 2) * 0.5, 2.0)
            risk_factors.append({
                "factor": "Multiple Source IPs",
                "score": factor_score,
                "details": f"Login from {distinct_ips} different IP addresses"
            })
            risk_score += factor_score
        
        # Factor 4: Number of distinct hosts accessed
        distinct_hosts = user_df['dest_host'].nunique()
        if distinct_hosts > 3:
            factor_score = min((distinct_hosts - 3) * 0.3, 1.5)
            risk_factors.append({
                "factor": "Multiple Host Access",
                "score": factor_score,
                "details": f"Accessed {distinct_hosts} different hosts"
            })
            risk_score += factor_score
        
        # Factor 5: Check for any access to high-criticality assets
        assets = list(db.assets.find({"criticality": {"$gte": 4}}))
        high_criticality_hosts = set([asset['host'] for asset in assets])
        accessed_critical = user_df[user_df['dest_host'].isin(high_criticality_hosts)]
        
        if not accessed_critical.empty:
            factor_score = 1.5
            risk_factors.append({
                "factor": "Critical Asset Access",
                "score": factor_score,
                "details": f"Accessed {accessed_critical['dest_host'].nunique()} critical assets"
            })
            risk_score += factor_score
        
        # Save user risk score
        risk_scores.append({
            "entity_id": user,
            "entity_type": EntityType.USER,
            "risk_score": min(risk_score, 10.0),  # Cap at 10.0
            "risk_factors": risk_factors,
            "last_updated": end_time,
            "metadata": {
                "login_count": user_df.shape[0],
                "failure_count": failed_attempts,
                "distinct_ips": distinct_ips,
                "distinct_hosts": distinct_hosts
            }
        })
    
    return risk_scores

def calculate_ip_risk_scores(db, start_time, end_time) -> List[Dict[str, Any]]:
    """Calculate risk scores for IP entities"""
    # Get logs
    auth_logs = list(db.auth_logs.find({"timestamp": {"$gte": start_time, "$lte": end_time}}))
    network_logs = list(db.network_logs.find({"timestamp": {"$gte": start_time, "$lte": end_time}}))
    
    if not auth_logs and not network_logs:
        logger.info("No logs found for IP risk scoring")
        return []
    
    # Convert to DataFrames
    auth_df = pd.DataFrame(auth_logs) if auth_logs else pd.DataFrame()
    network_df = pd.DataFrame(network_logs) if network_logs else pd.DataFrame()
    
    # Get all IPs from both log types
    all_ips = set()
    if not auth_df.empty:
        all_ips.update(auth_df['src_ip'].unique())
    
    if not network_df.empty:
        all_ips.update(network_df['src_ip'].unique())
        all_ips.update(network_df['dest_ip'].unique())
    
    # Get threat intel data
    threat_intel = {item['indicator']: item for item in db.threat_intel.find({"type": "IP"})}
    
    # Risk factors and scores
    risk_scores = []
    
    for ip in all_ips:
        risk_factors = []
        risk_score = 0.0
        
        # Factor 1: Check if IP is in threat intelligence
        if ip in threat_intel:
            intel = threat_intel[ip]
            factor_score = min(intel['threat_level'] / 10.0 * 5.0, 5.0)
            risk_factors.append({
                "factor": "Threat Intelligence Match",
                "score": factor_score,
                "details": f"IP found in threat intel with score {intel['threat_level']}/10"
            })
            risk_score += factor_score
        
        # Factor 2: Failed authentication attempts
        if not auth_df.empty:
            ip_auth_df = auth_df[auth_df['src_ip'] == ip]
            failed_attempts = ip_auth_df[ip_auth_df['status'] == 'FAILURE'].shape[0]
            
            if failed_attempts > 0:
                factor_score = min(failed_attempts * 0.8, 3.0)
                risk_factors.append({
                    "factor": "Failed Login Attempts",
                    "score": factor_score,
                    "details": f"{failed_attempts} failed login attempts from this IP"
                })
                risk_score += factor_score
            
            # Factor 3: Number of distinct users accessed by this IP
            distinct_users = ip_auth_df['username'].nunique()
            if distinct_users > 2:
                factor_score = min((distinct_users - 2) * 0.5, 2.0)
                risk_factors.append({
                    "factor": "Multiple User Access",
                    "score": factor_score,
                    "details": f"IP used by {distinct_users} different user accounts"
                })
                risk_score += factor_score
        
        # Factor 4: Check network logs for potential port scanning
        if not network_df.empty:
            ip_network_df = network_df[network_df['src_ip'] == ip]
            
            if not ip_network_df.empty:
                # Count distinct destination ports per IP
                distinct_ports = ip_network_df['dest_port'].nunique()
                if distinct_ports > 5:
                    factor_score = min((distinct_ports - 5) * 0.3, 2.0)
                    risk_factors.append({
                        "factor": "Potential Port Scanning",
                        "score": factor_score,
                        "details": f"IP accessed {distinct_ports} different ports"
                    })
                    risk_score += factor_score
                
                # Factor 5: Number of denied connections
                denied_conns = ip_network_df[ip_network_df['action'] == 'DENY'].shape[0]
                if denied_conns > 0:
                    factor_score = min(denied_conns * 0.5, 2.0)
                    risk_factors.append({
                        "factor": "Denied Connections",
                        "score": factor_score,
                        "details": f"{denied_conns} connection attempts were denied"
                    })
                    risk_score += factor_score
                
                # Factor 6: Traffic labeled as attack
                attack_traffic = ip_network_df[ip_network_df['label'] == 'attack'].shape[0]
                if attack_traffic > 0:
                    factor_score = min(attack_traffic * 1.0, 3.0)
                    risk_factors.append({
                        "factor": "Labeled Attack Traffic",
                        "score": factor_score,
                        "details": f"{attack_traffic} connections labeled as attacks"
                    })
                    risk_score += factor_score
        
        # Save IP risk score
        metadata = {}
        
        if not auth_df.empty:
            ip_auth_df = auth_df[auth_df['src_ip'] == ip]
            if not ip_auth_df.empty:
                metadata["auth_count"] = ip_auth_df.shape[0]
                metadata["auth_failures"] = ip_auth_df[ip_auth_df['status'] == 'FAILURE'].shape[0]
                metadata["users_accessed"] = ip_auth_df['username'].nunique()
        
        if not network_df.empty:
            src_ip_network_df = network_df[network_df['src_ip'] == ip]
            dest_ip_network_df = network_df[network_df['dest_ip'] == ip]
            
            if not src_ip_network_df.empty:
                metadata["outbound_connections"] = src_ip_network_df.shape[0]
                metadata["outbound_denied"] = src_ip_network_df[src_ip_network_df['action'] == 'DENY'].shape[0]
            
            if not dest_ip_network_df.empty:
                metadata["inbound_connections"] = dest_ip_network_df.shape[0]
                metadata["inbound_denied"] = dest_ip_network_df[dest_ip_network_df['action'] == 'DENY'].shape[0]
        
        risk_scores.append({
            "entity_id": ip,
            "entity_type": EntityType.IP,
            "risk_score": min(risk_score, 10.0),  # Cap at 10.0
            "risk_factors": risk_factors,
            "last_updated": end_time,
            "metadata": metadata
        })
    
    return risk_scores

def calculate_host_risk_scores(db, start_time, end_time) -> List[Dict[str, Any]]:
    """Calculate risk scores for host entities"""
    # Get logs
    auth_logs = list(db.auth_logs.find({"timestamp": {"$gte": start_time, "$lte": end_time}}))
    
    if not auth_logs:
        logger.info("No logs found for host risk scoring")
        return []
    
    # Convert to DataFrame
    auth_df = pd.DataFrame(auth_logs)
    
    # Get all hosts
    hosts = auth_df['dest_host'].unique()
    
    # Get asset information
    assets = {asset['host']: asset for asset in db.assets.find({})}
    
    # Risk factors and scores
    risk_scores = []
    
    for host in hosts:
        host_df = auth_df[auth_df['dest_host'] == host]
        
        # Calculate risk factors
        risk_factors = []
        risk_score = 0.0
        
        # Factor 1: Base score based on asset criticality
        asset_info = assets.get(host, {"criticality": 1})
        criticality = asset_info.get("criticality", 1)
        base_score = criticality * 0.5
        
        risk_factors.append({
            "factor": "Asset Criticality",
            "score": base_score,
            "details": f"Asset criticality level: {criticality}/5"
        })
        risk_score += base_score
        
        # Factor 2: Failed login attempts
        failed_attempts = host_df[host_df['status'] == 'FAILURE'].shape[0]
        if failed_attempts > 0:
            factor_score = min(failed_attempts * 0.5, 2.5)
            risk_factors.append({
                "factor": "Failed Login Attempts",
                "score": factor_score,
                "details": f"{failed_attempts} failed login attempts to this host"
            })
            risk_score += factor_score
        
        # Factor 3: Number of distinct users
        distinct_users = host_df['username'].nunique()
        if distinct_users > 3:
            factor_score = min((distinct_users - 3) * 0.3, 1.5)
            risk_factors.append({
                "factor": "Multiple User Access",
                "score": factor_score,
                "details": f"{distinct_users} different users accessed this host"
            })
            risk_score += factor_score
        
        # Factor 4: Number of distinct source IPs
        distinct_ips = host_df['src_ip'].nunique()
        if distinct_ips > 5:
            factor_score = min((distinct_ips - 5) * 0.3, 1.5)
            risk_factors.append({
                "factor": "Multiple Source IPs",
                "score": factor_score,
                "details": f"{distinct_ips} different IPs accessed this host"
            })
            risk_score += factor_score
        
        # Factor 5: Check for threat intel matches in source IPs
        threat_ips = set(item['indicator'] for item in db.threat_intel.find({"type": "IP"}))
        malicious_sources = host_df[host_df['src_ip'].isin(threat_ips)]
        
        if not malicious_sources.empty:
            factor_score = 3.0
            risk_factors.append({
                "factor": "Malicious Source IPs",
                "score": factor_score,
                "details": f"{malicious_sources['src_ip'].nunique()} known malicious IPs accessed this host"
            })
            risk_score += factor_score
        
        # Save host risk score
        risk_scores.append({
            "entity_id": host,
            "entity_type": EntityType.HOST,
            "risk_score": min(risk_score, 10.0),  # Cap at 10.0
            "risk_factors": risk_factors,
            "last_updated": end_time,
            "metadata": {
                "login_count": host_df.shape[0],
                "failure_count": failed_attempts,
                "distinct_users": distinct_users,
                "distinct_source_ips": distinct_ips,
                "owner": assets.get(host, {}).get("owner", "Unknown"),
                "criticality": criticality
            }
        })
    
    return risk_scores
