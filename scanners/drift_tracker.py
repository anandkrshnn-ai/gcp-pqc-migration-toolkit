import sqlite3
import os
from typing import Dict, Any

DB_PATH = "pqc_drift_history.db"

def init_db():
    """Initializes the database schema if it doesn't already exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Scan history table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        project_id TEXT NOT NULL,
        maturity_score INTEGER NOT NULL,
        total_assets INTEGER NOT NULL,
        compliant_assets INTEGER NOT NULL
    );
    """)
    
    # Asset history table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS asset_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        resource_name TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        algorithm TEXT NOT NULL,
        status TEXT NOT NULL,
        crypto_classification TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scan_history(id)
    );
    """)
    
    conn.commit()
    conn.close()

def record_scan(project_id: str, findings: list[dict]) -> int:
    """Saves a point-in-time compliance report scan to the history database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    total = len(findings)
    compliant = sum(1 for f in findings if f.get("crypto_classification") in ["NATIVE_PQC", "HYBRID"])
    maturity_score = int((compliant / total) * 100) if total > 0 else 0
    
    # Insert scan history
    cursor.execute("""
    INSERT INTO scan_history (project_id, maturity_score, total_assets, compliant_assets)
    VALUES (?, ?, ?, ?)
    """, (project_id, maturity_score, total, compliant))
    
    scan_id = cursor.lastrowid
    
    # Insert individual asset history
    for f in findings:
        cursor.execute("""
        INSERT INTO asset_history (scan_id, resource_name, resource_type, algorithm, status, crypto_classification)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            f.get("resource_name"),
            f.get("resource_type"),
            f.get("algorithm"),
            f.get("status"),
            f.get("crypto_classification")
        ))
        
    conn.commit()
    conn.close()
    return scan_id

def check_for_drift(project_id: str, new_findings: list[dict]) -> dict:
    """Compares the new scan against the latest recorded historical scan for a project."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get the latest scan
    cursor.execute("""
    SELECT id, maturity_score FROM scan_history
    WHERE project_id = ?
    ORDER BY timestamp DESC LIMIT 1
    """, (project_id,))
    
    latest_scan = cursor.fetchone()
    if not latest_scan:
        conn.close()
        return {
            "drift_detected": False,
            "previous_maturity_score": None,
            "new_maturity_score": 0,
            "score_delta": 0,
            "newly_classical_assets": [],
            "downgraded_assets": []
        }
        
    prev_scan_id, prev_maturity = latest_scan
    
    # Load assets from the previous scan
    cursor.execute("""
    SELECT resource_name, crypto_classification FROM asset_history
    WHERE scan_id = ?
    """, (prev_scan_id,))
    
    prev_assets = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    
    # Calculate new maturity score
    total = len(new_findings)
    compliant = sum(1 for f in new_findings if f.get("crypto_classification") in ["NATIVE_PQC", "HYBRID"])
    new_maturity = int((compliant / total) * 100) if total > 0 else 0
    
    newly_classical_assets = []
    downgraded_assets = []
    
    for f in new_findings:
        name = f.get("resource_name")
        curr_class = f.get("crypto_classification")
        
        if name in prev_assets:
            prev_class = prev_assets[name]
            # Checked if it downgraded from PQC/Hybrid to Classical
            if prev_class in ["NATIVE_PQC", "HYBRID"] and curr_class == "CLASSICAL":
                downgraded_assets.append(name)
        else:
            # Newly introduced asset that is Classical (not PQC ready)
            if curr_class == "CLASSICAL":
                newly_classical_assets.append(name)
                
    drift_detected = (new_maturity < prev_maturity) or len(newly_classical_assets) > 0 or len(downgraded_assets) > 0
    
    return {
        "drift_detected": drift_detected,
        "previous_maturity_score": prev_maturity,
        "new_maturity_score": new_maturity,
        "score_delta": new_maturity - prev_maturity,
        "newly_classical_assets": newly_classical_assets,
        "downgraded_assets": downgraded_assets
    }

def get_scan_history(project_id: str) -> list[Dict[str, Any]]:
    """Returns a list of point-in-time scan histories for trend lines."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT timestamp, maturity_score, total_assets, compliant_assets FROM scan_history
    WHERE project_id = ?
    ORDER BY timestamp ASC
    """, (project_id,))
    
    history = []
    for row in cursor.fetchall():
        history.append({
            "timestamp": row[0],
            "maturity_score": row[1],
            "total_assets": row[2],
            "compliant_assets": row[3]
        })
    conn.close()
    return history
