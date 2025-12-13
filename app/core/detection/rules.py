from datetime import datetime, timedelta
from typing import List, Dict, Any

from pymongo.database import Database
from bson.objectid import ObjectId

async def detect_auth_anomalies(db: Database, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
    """Detect authentication anomalies using rule-based methods"""
    alerts = []
    
    # Rule 1: Detect multiple authentication failures from same IP
    pipeline = [
        {
            "$match": {
                "timestamp": {"$gte": start_time, "$lte": end_time},
                "status": "FAILURE"
            }
        },
        {
            "$group": {
                "_id": {
                    "src_ip": "$src_ip",
                    "username": "$username"
                },
                "count": {"$sum": 1},
                "timestamps": {"$push": "$timestamp"},
                "first_timestamp": {"$min": "$timestamp"},
                "last_timestamp": {"$max": "$timestamp"},
                "documents": {"$push": "$$ROOT"}
            }
        },
        {
            "$match": {
                "count": {"$gte": 3}
            }
        },
        {
            "$sort": {"count": -1}
            
        }
    ]
    
    auth_failure_groups = await db.auth_logs.aggregate(pipeline).to_list(100)
    
    for group in auth_failure_groups:
        src_ip = group["_id"]["src_ip"]
        username = group["_id"]["username"]
        count = group["count"]
        first_timestamp = group["first_timestamp"]
        last_timestamp = group["last_timestamp"]
        
        # Check if within short time window (less than 10 minutes)
        time_window = (last_timestamp - first_timestamp).total_seconds() / 60
        
        if time_window < 10:
            severity = "HIGH" if count >= 5 else "MEDIUM"
            
            alert = {
                "timestamp": last_timestamp,
                "title": f"Multiple Authentication Failures: {username}",
                "description": f"{count} failed authentication attempts for user {username} from {src_ip} within {time_window:.1f} minutes",
                "source_log_id": str(group["documents"][0]["_id"]),
                "log_type": "AUTH",
                "severity": severity,
                "status": "NEW",
                "entities": [
                    {"type": "USER", "value": username},
                    {"type": "IP", "value": src_ip}
                ],
                "tactic": "Credential Access",
                "technique": "Brute Force",
                "metadata": {
                    "failure_count": count,
                    "time_window_minutes": time_window,
                    "dest_hosts": list(set([doc["dest_host"] for doc in group["documents"]])),
                    "auth_methods": list(set([doc["auth_method"] for doc in group["documents"]]))
                }
            }
            
            alerts.append(alert)
    
    # Rule 2: Detect successful authentication after failures
    pipeline = [
        {
            "$match": {
                "timestamp": {"$gte": start_time, "$lte": end_time}
            }
        },
        {
            "$sort": {"timestamp": 1}
        },
        {
            "$group": {
                "_id": {
                    "src_ip": "$src_ip",
                    "username": "$username"
                },
                "auth_attempts": {"$push": {
                    "status": "$status",
                    "timestamp": "$timestamp",
                    "auth_method": "$auth_method",
                    "dest_host": "$dest_host",
                    "doc_id": "$_id"
                }}
            }
        }
    ]
    
    auth_sequences = await db.auth_logs.aggregate(pipeline).to_list(500)
    
    for sequence in auth_sequences:
        src_ip = sequence["_id"]["src_ip"]
        username = sequence["_id"]["username"]
        attempts = sequence["auth_attempts"]
        
        # Look for failure followed by success within 10 minutes
        for i in range(len(attempts) - 1):
            if (attempts[i]["status"] == "FAILURE" and 
                attempts[i+1]["status"] == "SUCCESS" and
                (attempts[i+1]["timestamp"] - attempts[i]["timestamp"]).total_seconds() < 600):
                
                alert = {
                    "timestamp": attempts[i+1]["timestamp"],
                    "title": f"Success After Failure: {username}",
                    "description": f"Successful authentication for {username} from {src_ip} after previous failure",
                    "source_log_id": str(attempts[i+1]["doc_id"]),
                    "log_type": "AUTH",
                    "severity": "MEDIUM",
                    "status": "NEW",
                    "entities": [
                        {"type": "USER", "value": username},
                        {"type": "IP", "value": src_ip},
                        {"type": "HOST", "value": attempts[i+1]["dest_host"]}
                    ],
                    "tactic": "Initial Access",
                    "technique": "Valid Accounts",
                    "metadata": {
                        "time_between_attempts_seconds": (attempts[i+1]["timestamp"] - attempts[i]["timestamp"]).total_seconds(),
                        "failure_method": attempts[i]["auth_method"],
                        "success_method": attempts[i+1]["auth_method"],
                        "dest_host": attempts[i+1]["dest_host"]
                    }
                }
                
                alerts.append(alert)
                break
    
    return alerts

async def detect_network_anomalies(db: Database, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
    """Detect network anomalies using rule-based methods"""
    alerts = []
    
    # Rule 1: Detect port scans (multiple ports to same destination)
    pipeline = [
        {
            "$match": {
                "timestamp": {"$gte": start_time, "$lte": end_time}
            }
        },
        {
            "$group": {
                "_id": {
                    "src_ip": "$src_ip",
                    "dest_ip": "$dest_ip"
                },
                "port_count": {"$addToSet": "$dest_port"},
                "protocols": {"$addToSet": "$protocol"},
                "first_timestamp": {"$min": "$timestamp"},
                "last_timestamp": {"$max": "$timestamp"},
                "log_ids": {"$push": "$_id"}
            }
        },
        {
            "$match": {
                "$expr": {"$gte": [{"$size": "$port_count"}, 5]}
            }
        },
        {
            "$sort": {"port_count": -1}
        }
    ]
    
    port_scan_groups = await db.network_logs.aggregate(pipeline).to_list(100)
    
    for group in port_scan_groups:
        src_ip = group["_id"]["src_ip"]
        dest_ip = group["_id"]["dest_ip"]
        port_count = len(group["port_count"])
        time_window = (group["last_timestamp"] - group["first_timestamp"]).total_seconds() / 60
        
        # Higher severity if scan happened quickly
        severity = "HIGH" if time_window < 10 else "MEDIUM"
        
        alert = {
            "timestamp": group["last_timestamp"],
            "title": f"Potential Port Scan: {dest_ip}",
            "description": f"Detected {port_count} different ports accessed from {src_ip} to {dest_ip} within {time_window:.1f} minutes",
            "source_log_id": str(group["log_ids"][0]),
            "log_type": "NETWORK",
            "severity": severity,
            "status": "NEW",
            "entities": [
                {"type": "IP", "value": src_ip},
                {"type": "IP", "value": dest_ip}
            ],
            "tactic": "Discovery",
            "technique": "Network Service Scanning",
            "metadata": {
                "port_count": port_count,
                "protocols": group["protocols"],
                "time_window_minutes": time_window,
                "ports": sorted(group["port_count"])[:20]  # Show first 20 ports
            }
        }
        
        alerts.append(alert)
    
    # Rule 2: Detect high-volume traffic
    pipeline = [
        {
            "$match": {
                "timestamp": {"$gte": start_time, "$lte": end_time}
            }
        },
        {
            "$group": {
                "_id": {
                    "src_ip": "$src_ip",
                    "dest_ip": "$dest_ip"
                },
                "total_bytes_sent": {"$sum": "$bytes_sent"},
                "total_bytes_received": {"$sum": "$bytes_received"},
                "first_timestamp": {"$min": "$timestamp"},
                "last_timestamp": {"$max": "$timestamp"},
                "log_ids": {"$push": "$_id"},
                "connection_count": {"$sum": 1}
            }
        },
        {
            "$match": {
                "$expr": {
                    "$or": [
                        {"$gt": ["$total_bytes_sent", 1000000]},  # 1MB+
                        {"$gt": ["$total_bytes_received", 1000000]}
                    ]
                }
            }
        },
        {
            "$sort": {"total_bytes_sent": -1}
        }
    ]
    
    high_volume_groups = await db.network_logs.aggregate(pipeline).to_list(100)
    
    for group in high_volume_groups:
        src_ip = group["_id"]["src_ip"]
        dest_ip = group["_id"]["dest_ip"]
        time_window = (group["last_timestamp"] - group["first_timestamp"]).total_seconds() / 60
        total_bytes = group["total_bytes_sent"] + group["total_bytes_received"]
        mb_transferred = total_bytes / (1024 * 1024)
        
        # Only alert if this happened within a short time window
        if time_window < 60:  # Less than 1 hour
            alert = {
                "timestamp": group["last_timestamp"],
                "title": f"High Volume Data Transfer",
                "description": f"High volume data transfer ({mb_transferred:.2f} MB) between {src_ip} and {dest_ip} within {time_window:.1f} minutes",
                "source_log_id": str(group["log_ids"][0]),
                "log_type": "NETWORK",
                "severity": "MEDIUM",
                "status": "NEW",
                "entities": [
                    {"type": "IP", "value": src_ip},
                    {"type": "IP", "value": dest_ip}
                ],
                "tactic": "Exfiltration",
                "technique": "Data Transfer Size Limits",
                "metadata": {
                    "bytes_sent": group["total_bytes_sent"],
                    "bytes_received": group["total_bytes_received"],
                    "total_mb": mb_transferred,
                    "time_window_minutes": time_window,
                    "connection_count": group["connection_count"]
                }
            }
            
            alerts.append(alert)
    
    return alerts

async def detect_threat_intel_matches(db: Database, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
    """Detect matches with threat intelligence"""
    alerts = []
    
    # Get all threat intel indicators
    threat_intel = await db.threat_intel.find({"type": "IP"}).to_list(1000)
    threat_ips = {item["indicator"]: item for item in threat_intel}
    
    if not threat_ips:
        return []
    
    # Check network logs for matches
    pipeline = [
        {
            "$match": {
                "timestamp": {"$gte": start_time, "$lte": end_time},
                "$or": [
                    {"src_ip": {"$in": list(threat_ips.keys())}},
                    {"dest_ip": {"$in": list(threat_ips.keys())}}
                ]
            }
        }
    ]
    
    network_matches = await db.network_logs.find({
        "timestamp": {"$gte": start_time, "$lte": end_time},
        "$or": [
            {"src_ip": {"$in": list(threat_ips.keys())}},
            {"dest_ip": {"$in": list(threat_ips.keys())}}
        ]
    }).to_list(1000)
    
    # Check auth logs for matches
    auth_matches = await db.auth_logs.find({
        "timestamp": {"$gte": start_time, "$lte": end_time},
        "src_ip": {"$in": list(threat_ips.keys())}
    }).to_list(1000)
    
    # Generate alerts for network matches
    for log in network_matches:
        matched_ip = None
        if log["src_ip"] in threat_ips:
            matched_ip = log["src_ip"]
        elif log["dest_ip"] in threat_ips:
            matched_ip = log["dest_ip"]
        
        if matched_ip:
            threat_info = threat_ips[matched_ip]
            
            alert = {
                "timestamp": log["timestamp"],
                "title": f"Threat Intel Match: {matched_ip}",
                "description": f"Traffic involving known malicious IP {matched_ip} (Threat Level: {threat_info['threat_level']}/10)",
                "source_log_id": str(log["_id"]),
                "log_type": "NETWORK",
                "severity": "CRITICAL" if threat_info["threat_level"] >= 8 else "HIGH",
                "status": "NEW",
                "entities": [
                    {"type": "IP", "value": log["src_ip"]},
                    {"type": "IP", "value": log["dest_ip"]}
                ],
                "tactic": "Command and Control",
                "technique": "Application Layer Protocol",
                "metadata": {
                    "threat_level": threat_info["threat_level"],
                    "threat_source": threat_info["source"],
                    "first_seen": threat_info["first_seen"],
                    "last_seen": threat_info["last_seen"],
                    "protocol": log["protocol"],
                    "dest_port": log["dest_port"],
                    "action": log["action"]
                }
            }
            
            alerts.append(alert)
    
    # Generate alerts for auth matches
    for log in auth_matches:
        matched_ip = log["src_ip"]
        threat_info = threat_ips[matched_ip]
        
        alert = {
            "timestamp": log["timestamp"],
            "title": f"Threat Intel Match: {matched_ip}",
            "description": f"Authentication attempt from known malicious IP {matched_ip} (Threat Level: {threat_info['threat_level']}/10)",
            "source_log_id": str(log["_id"]),
            "log_type": "AUTH",
            "severity": "CRITICAL" if threat_info["threat_level"] >= 8 else "HIGH",
            "status": "NEW",
            "entities": [
                {"type": "IP", "value": log["src_ip"]},
                {"type": "USER", "value": log["username"]},
                {"type": "HOST", "value": log["dest_host"]}
            ],
            "tactic": "Initial Access",
            "technique": "Valid Accounts",
            "metadata": {
                "threat_level": threat_info["threat_level"],
                "threat_source": threat_info["source"],
                "first_seen": threat_info["first_seen"],
                "last_seen": threat_info["last_seen"],
                "auth_status": log["status"],
                "auth_method": log["auth_method"]
            }
        }
        
        alerts.append(alert)
    
    return alerts
