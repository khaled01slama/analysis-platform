def save_vulnerabilities(self, analysis_id: int, vulnerabilities: list[dict]) -> None:
        """
        Save vulnerabilities with CVE, patch link, and CVSS score for prioritization.
        Args:
            analysis_id: ID of the associated analysis
            vulnerabilities: List of vulnerability dicts with keys: cve_id, description, severity, cvss_score, patch_link, source
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        for vuln in vulnerabilities:
            cursor.execute('''
                INSERT INTO vulnerabilities (analysis_id, cve_id, description, severity, cvss_score, patch_link, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_id,
                vuln.get('cve_id'),
                vuln.get('description'),
                vuln.get('severity'),
                vuln.get('cvss_score'),
                vuln.get('patch_link'),
                vuln.get('source')
            ))
        conn.commit()
        conn.close()
"""
Database and Analysis Integration for Vulnerability Correlation Agent

This module provides:
1. Centralized data management for the Correlation Agent
   - Store and retrieve analysis results (Vanir, Joern, SBOM)
   - Manage analysis history (date, repo, mode, results)
   - Generate reports and statistics

2. Integration of analysis tools with database
   - Centralized analysis execution
   - Automatic result storage
   - Unified interface for different tools
"""

import os
import sys
import json
import time
import sqlite3
import logging
import tempfile
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional, Callable
from pathlib import Path

# Import local modules
# Removed circular import - CorrelationAgent will be imported when needed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("db_integration")

# Try to import SBOM analyzer
try:
    # The SBOM analyzer is now in the separated sbom_analyzer directory
    current_dir = os.path.dirname(os.path.abspath(__file__))  # correlation_engine
    analysis_root = os.path.dirname(current_dir)  # analysis
    sbom_path = os.path.join(analysis_root, "sbom_analyzer")  # sbom_analyzer
    sys.path.append(sbom_path)
    from analyzer import SBOMAnalyzer
    from converter import convert_spdx_to_json
    SBOM_AVAILABLE = True
except ImportError as e:
    logger.warning(f"SBOM analyzer not available: {str(e)}")
    SBOM_AVAILABLE = False


class AnalysisDatabase:
    """Database manager for vulnerability analysis data."""
    
    def __init__(self, db_path: str = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to database file. 
                    Defaults to creating a file in the data folder.
        """
        if db_path is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))  
            tools_dir = os.path.dirname(current_dir)  
            data_dir = os.path.join(tools_dir, "data")  
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, "correlation_analysis.db")
        
        self.db_path = db_path
        db_exists = os.path.exists(self.db_path)
        if not db_exists:
            logger.info(f"Création d'une nouvelle base de données à {self.db_path}")
        else:
            logger.info(f"Connexion à la base de données existante à {self.db_path}")
            # Migrer la base de données si nécessaire
            self._migrate_database()
            
        # Dans tous les cas, initialiser la structure de la BD (avec IF NOT EXISTS)
        self._initialize_db()
    
    def _migrate_database(self):
        """Migrate database to remove username and user_id columns and add new vanir columns."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if username and user_id columns exist
            cursor.execute('PRAGMA table_info(analysis)')
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            
            if 'username' in column_names or 'user_id' in column_names:
                logger.info("Database migration: removing username and user_id columns")
                
                # Create new table without username and user_id
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_path TEXT NOT NULL,
                    analysis_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    duration_seconds INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Copy data without username and user_id columns
                cursor.execute('''
                INSERT INTO analysis_new (id, repo_path, analysis_type, status, duration_seconds, created_at)
                SELECT id, repo_path, analysis_type, status, duration_seconds, created_at FROM analysis
                ''')
                
                # Drop old table and rename new one
                cursor.execute('DROP TABLE analysis')
                cursor.execute('ALTER TABLE analysis_new RENAME TO analysis')
                
                logger.info("Successfully removed username and user_id columns")
                
            # Check if vanir_results table needs new columns
            cursor.execute('PRAGMA table_info(vanir_results)')
            vanir_columns = cursor.fetchall()
            vanir_column_names = [col[1] for col in vanir_columns]
            
            # Add patch_links column if it doesn't exist
            if 'patch_links' not in vanir_column_names:
                logger.info("Database migration: adding patch_links column to vanir_results")
                cursor.execute('ALTER TABLE vanir_results ADD COLUMN patch_links TEXT')
                
            # Add cve_ids column if it doesn't exist
            if 'cve_ids' not in vanir_column_names:
                logger.info("Database migration: adding cve_ids column to vanir_results")
                cursor.execute('ALTER TABLE vanir_results ADD COLUMN cve_ids TEXT')
                
        except Exception as e:
            logger.error(f"Database migration failed: {str(e)}")
            # Don't fail completely, let the system continue
        finally:
            conn.commit()
            conn.close()
    
    def _initialize_db(self):
        """Initialize database structure."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Analysis table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            analysis_type TEXT NOT NULL,
            status TEXT NOT NULL,
            duration_seconds INTEGER
        )
        ''')
        
        # Vanir results table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vanir_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            vulnerability_count INTEGER NOT NULL,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            patch_links TEXT,
            cve_ids TEXT,
            raw_results TEXT,
            FOREIGN KEY (analysis_id) REFERENCES analysis(id)
        )
        ''')
        
        # Joern results table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS joern_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            unused_functions_count INTEGER NOT NULL,
            raw_results TEXT,
            FOREIGN KEY (analysis_id) REFERENCES analysis(id)
        )
        ''')
        
        # Correlation results table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS correlation_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            vanir_id INTEGER,
            joern_id INTEGER,
            high_risk_count INTEGER DEFAULT 0,
            medium_risk_count INTEGER DEFAULT 0,
            low_risk_count INTEGER DEFAULT 0,
            raw_results TEXT,
            FOREIGN KEY (analysis_id) REFERENCES analysis(id),
            FOREIGN KEY (vanir_id) REFERENCES vanir_results(id),
            FOREIGN KEY (joern_id) REFERENCES joern_results(id)
        )
        ''')
        
        # SBOM results table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sbom_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            package_count INTEGER NOT NULL,
            vulnerability_count INTEGER NOT NULL,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            raw_results TEXT,
            FOREIGN KEY (analysis_id) REFERENCES analysis(id)
        )
        ''')
        
        # Vulnerabilities table for CVE prioritization
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            cve_id TEXT,
            description TEXT,
            severity TEXT,
            cvss_score REAL,
            patch_link TEXT,
            source TEXT,
            FOREIGN KEY (analysis_id) REFERENCES analysis(id)
        )
        ''')
        # Comments and tags table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_meta (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            comments TEXT,
            tags TEXT,
            favorite BOOLEAN DEFAULT 0,
            FOREIGN KEY (analysis_id) REFERENCES analysis(id)
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_analysis(self, repo_path: str, analysis_type: str) -> int:
        """
        Create a new analysis entry in the database.
        
        # Security agent memory table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_agent_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT,
            analysis_id INTEGER,
            FOREIGN KEY (analysis_id) REFERENCES analysis(id)
        )
        ''')

        # Security agent state table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS agent_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            value TEXT,
            updated_at TEXT
        )
        ''')
        Args:
            repo_path: Path to the analyzed repository
            analysis_type: Type of analysis (vanir_only, joern_only, integrated, sbom_only, etc.)
            
        Returns:
            ID of the created analysis
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO analysis 
        (timestamp, repo_path, analysis_type, status)
        VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(), 
            repo_path,
            analysis_type,
            "running"
        ))
        
        analysis_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return analysis_id
    
    def update_analysis_status(self, analysis_id: int, status: str, duration_seconds: int = None) -> None:
        """
        Met à jour le statut d'une analyse.
        
        Args:
            analysis_id: ID de l'analyse à mettre à jour
            status: Nouveau statut (running, completed, failed)
            duration_seconds: Durée en secondes (optionnel)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if duration_seconds is not None:
            cursor.execute('''
            UPDATE analysis SET status = ?, duration_seconds = ?
            WHERE id = ?
            ''', (status, duration_seconds, analysis_id))
        else:
            cursor.execute('''
            UPDATE analysis SET status = ?
            WHERE id = ?
            ''', (status, analysis_id))
        
        conn.commit()
        conn.close()
    
    def save_vanir_results(self, analysis_id: int, vulnerabilities: List[Dict], 
                           raw_results: str = None, summary: Dict = None) -> int:
        """
        Enregistre les résultats d'analyse Vanir.
        
        Args:
            analysis_id: ID de l'analyse associée
            vulnerabilities: Liste des vulnérabilités
            raw_results: Résultats bruts (optionnel)
            summary: Résumé des résultats (optionnel)
            
        Returns:
            ID du résultat Vanir créé
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Comptage des vulnérabilités par sévérité
        if summary:
            critical_count = summary.get("critical", 0)
            high_count = summary.get("high", 0)
            medium_count = summary.get("medium", 0)
            low_count = summary.get("low", 0)
        else:
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0
            
            # Comptage manuel si pas de résumé fourni
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "").upper()
                if severity == "CRITICAL":
                    critical_count += 1
                elif severity == "HIGH":
                    high_count += 1
                elif severity == "MEDIUM":
                    medium_count += 1
                else:
                    low_count += 1
        
        # Extract patch links and CVE IDs from vulnerabilities
        patch_links = []
        cve_ids = []
        
        for vuln in vulnerabilities:
            # Extract patch link if available
            patch_link = vuln.get("patch_link") or vuln.get("fix_link") or vuln.get("remediation_link")
            if patch_link:
                patch_links.append(patch_link)
            
            # Extract CVE ID if available
            cve_id = vuln.get("cve_id") or vuln.get("cve") or vuln.get("vulnerability_id")
            if cve_id:
                cve_ids.append(cve_id)
        
        # Convert lists to JSON strings for storage
        patch_links_json = json.dumps(patch_links) if patch_links else None
        cve_ids_json = json.dumps(cve_ids) if cve_ids else None
        
        cursor.execute('''
        INSERT INTO vanir_results 
        (analysis_id, vulnerability_count, critical_count, high_count, medium_count, low_count, patch_links, cve_ids, raw_results)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis_id, 
            len(vulnerabilities),
            critical_count,
            high_count,
            medium_count,
            low_count,
            patch_links_json,
            cve_ids_json,
            raw_results if raw_results else json.dumps({"vulnerabilities": vulnerabilities})
        ))
        
        vanir_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return vanir_id
    
    def save_joern_results(self, analysis_id: int, unused_functions: List[Dict]) -> int:
        """
        Enregistre les résultats d'analyse Joern.
        
        Args:
            analysis_id: ID de l'analyse associée
            unused_functions: Liste des fonctions inutilisées
            
        Returns:
            ID du résultat Joern créé
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO joern_results 
        (analysis_id, unused_functions_count, raw_results)
        VALUES (?, ?, ?)
        ''', (
            analysis_id, 
            len(unused_functions),
            json.dumps({"unused_functions": unused_functions})
        ))
        
        joern_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return joern_id
    
    def save_correlation_results(self, analysis_id: int, vanir_id: int, joern_id: int, 
                                correlations: List[Dict]) -> int:
        """
        Enregistre les résultats de corrélation entre Vanir et Joern.
        
        Args:
            analysis_id: ID de l'analyse associée
            vanir_id: ID des résultats Vanir
            joern_id: ID des résultats Joern
            correlations: Liste des corrélations entre vulnérabilités et fonctions
            
        Returns:
            ID du résultat de corrélation créé
        """
        high_risk = sum(1 for c in correlations if c.get('risk_level') == 'HIGH')
        medium_risk = sum(1 for c in correlations if c.get('risk_level') == 'MEDIUM')
        low_risk = sum(1 for c in correlations if c.get('risk_level') == 'LOW')
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO correlation_results 
        (analysis_id, vanir_id, joern_id, high_risk_count, medium_risk_count, low_risk_count, raw_results)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis_id,
            vanir_id,
            joern_id,
            high_risk,
            medium_risk,
            low_risk,
            json.dumps({"correlations": correlations})
        ))
        
        correlation_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return correlation_id
    
    def save_sbom_results(self, analysis_id: int, sbom_data: Dict) -> int:
        """
        Enregistre les résultats d'analyse SBOM.
        
        Args:
            analysis_id: ID de l'analyse associée
            sbom_data: Données d'analyse SBOM
            
        Returns:
            ID du résultat SBOM créé
        """
        vulnerabilities = sbom_data.get("vulnerabilities", [])
        packages = sbom_data.get("packages", [])
        
        # Comptage des vulnérabilités par sévérité
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").upper()
            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            else:
                low_count += 1
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO sbom_results 
        (analysis_id, package_count, vulnerability_count, critical_count, high_count, medium_count, low_count, raw_results)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis_id,
            len(packages),
            len(vulnerabilities),
            critical_count,
            high_count,
            medium_count,
            low_count,
            json.dumps(sbom_data)
        ))
        
        sbom_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return sbom_id
    
    def get_analysis_by_id(self, analysis_id: int) -> Dict:
        """
        Récupère les détails d'une analyse à partir de son ID.
        
        Args:
            analysis_id: ID de l'analyse à récupérer
            
        Returns:
            Dictionnaire contenant les détails de l'analyse
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM analysis WHERE id = ?
        ''', (analysis_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None
        
        analysis = dict(row)
        
        # Récupérer les résultats Vanir
        cursor.execute('''
        SELECT * FROM vanir_results WHERE analysis_id = ?
        ''', (analysis_id,))
        
        vanir_row = cursor.fetchone()
        if vanir_row:
            vanir = dict(vanir_row)
            vanir["raw_results"] = json.loads(vanir.get("raw_results", "{}"))
            analysis["vanir"] = vanir
        
        # Récupérer les résultats Joern
        cursor.execute('''
        SELECT * FROM joern_results WHERE analysis_id = ?
        ''', (analysis_id,))
        
        joern_row = cursor.fetchone()
        if joern_row:
            joern = dict(joern_row)
            joern["raw_results"] = json.loads(joern.get("raw_results", "{}"))
            analysis["joern"] = joern
        
        # Récupérer les résultats de corrélation
        cursor.execute('''
        SELECT * FROM correlation_results WHERE analysis_id = ?
        ''', (analysis_id,))
        
        corr_row = cursor.fetchone()
        if corr_row:
            correlation = dict(corr_row)
            correlation["raw_results"] = json.loads(correlation.get("raw_results", "{}"))
            analysis["correlation"] = correlation
        
        # Récupérer les résultats SBOM
        cursor.execute('''
        SELECT * FROM sbom_results WHERE analysis_id = ?
        ''', (analysis_id,))
        
        sbom_row = cursor.fetchone()
        if sbom_row:
            sbom = dict(sbom_row)
            sbom["raw_results"] = json.loads(sbom.get("raw_results", "{}"))
            analysis["sbom"] = sbom
        
        # Récupérer les métadonnées
        cursor.execute('''
        SELECT * FROM analysis_meta WHERE analysis_id = ?
        ''', (analysis_id,))
        
        meta_row = cursor.fetchone()
        if meta_row:
            meta = dict(meta_row)
            meta["tags"] = meta.get("tags", "").split(",") if meta.get("tags") else []
            analysis["meta"] = meta
        
        conn.close()
        return analysis
    
    def get_all_analyses(self, limit: int = None) -> List[Dict]:
        """
        Récupère la liste de toutes les analyses.
        
        Args:
            limit: Limite le nombre de résultats (optionnel)
            
        Returns:
            Liste des analyses
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if limit:
            cursor.execute('''
            SELECT * FROM analysis
            ORDER BY timestamp DESC
            LIMIT ?
            ''', (limit,))
        else:
            cursor.execute('''
            SELECT * FROM analysis
            ORDER BY timestamp DESC
            ''')
        
        rows = cursor.fetchall()
        analyses = []
        
        for row in rows:
            analysis = dict(row)
            
            # Récupérer les comptages
            cursor.execute('''
            SELECT vulnerability_count FROM vanir_results WHERE analysis_id = ?
            ''', (analysis["id"],))
            vanir_row = cursor.fetchone()
            if vanir_row:
                analysis["vulnerability_count"] = vanir_row[0]
            
            cursor.execute('''
            SELECT unused_functions_count FROM joern_results WHERE analysis_id = ?
            ''', (analysis["id"],))
            joern_row = cursor.fetchone()
            if joern_row:
                analysis["unused_functions_count"] = joern_row[0]
            
            # Comptage des vulnérabilités par risque
            cursor.execute('''
            SELECT high_risk_count, medium_risk_count, low_risk_count 
            FROM correlation_results WHERE analysis_id = ?
            ''', (analysis["id"],))
            corr_row = cursor.fetchone()
            if corr_row:
                analysis["high_risk"] = corr_row[0]
                analysis["medium_risk"] = corr_row[1]
                analysis["low_risk"] = corr_row[2]
            
            analyses.append(analysis)
        
        conn.close()
        return analyses

    def get_recent_analyses(self, days: int = 7, analysis_type: str = None, limit: int = None) -> List[Dict]:
        """
        Récupère les analyses récentes.
        
        Args:
            days: Nombre de jours à considérer
            analysis_type: Type d'analyse à filtrer (optionnel)
            limit: Nombre maximum d'analyses à récupérer (optionnel)
            
        Returns:
            Liste des analyses récentes
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Calculer la date limite
        date_limit = (datetime.now() - timedelta(days=days)).isoformat()
        
        if analysis_type and limit:
            cursor.execute('''
            SELECT * FROM analysis
            WHERE timestamp >= ? AND analysis_type = ?
            ORDER BY timestamp DESC
            LIMIT ?
            ''', (date_limit, analysis_type, limit))
        elif analysis_type:
            cursor.execute('''
            SELECT * FROM analysis
            WHERE timestamp >= ? AND analysis_type = ?
            ORDER BY timestamp DESC
            ''', (date_limit, analysis_type))
        elif limit:
            cursor.execute('''
            SELECT * FROM analysis
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT ?
            ''', (date_limit, limit))
        else:
            cursor.execute('''
            SELECT * FROM analysis
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            ''', (date_limit,))
        
        rows = cursor.fetchall()
        analyses = []
        
        for row in rows:
            analysis = dict(row)
            analyses.append(analysis)
        
        conn.close()
        return analyses
    
    def get_statistics(self) -> Dict:
        """
        Récupère des statistiques sur les analyses.
        
        Returns:
            Dictionnaire de statistiques
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Nombre total d'analyses
        cursor.execute('SELECT COUNT(*) FROM analysis')
        stats["total_analyses"] = cursor.fetchone()[0]
        
        # Répartition par type
        cursor.execute('''
        SELECT analysis_type, COUNT(*) as count 
        FROM analysis 
        GROUP BY analysis_type
        ''')
        stats["analysis_types"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Répartition par statut
        cursor.execute('''
        SELECT status, COUNT(*) as count 
        FROM analysis 
        GROUP BY status
        ''')
        stats["status_counts"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Nombre total de vulnérabilités
        cursor.execute('''
        SELECT SUM(vulnerability_count) FROM vanir_results
        ''')
        result = cursor.fetchone()
        stats["total_vulnerabilities"] = result[0] if result[0] else 0
        
        # Répartition des vulnérabilités par sévérité
        cursor.execute('''
        SELECT SUM(critical_count), SUM(high_count), 
               SUM(medium_count), SUM(low_count)
        FROM vanir_results
        ''')
        result = cursor.fetchone()
        if result[0]:
            stats["vulnerability_severity"] = {
                "critical": result[0] or 0,
                "high": result[1] or 0,
                "medium": result[2] or 0,
                "low": result[3] or 0
            }
        else:
            stats["vulnerability_severity"] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        
        # Nombre total de fonctions non utilisées
        cursor.execute('''
        SELECT SUM(unused_functions_count) FROM joern_results
        ''')
        result = cursor.fetchone()
        stats["total_unused_functions"] = result[0] if result[0] else 0
        
        # Durée moyenne des analyses
        cursor.execute('''
        SELECT AVG(duration_seconds) FROM analysis 
        WHERE duration_seconds IS NOT NULL AND status = 'completed'
        ''')
        result = cursor.fetchone()
        stats["avg_duration_seconds"] = result[0] if result[0] else 0
        
        conn.close()
        return stats
    
    def add_analysis_meta(self, analysis_id: int, comments: str = None, 
                        tags: List[str] = None, favorite: bool = False) -> None:
        """
        Ajoute des métadonnées à une analyse.
        
        Args:
            analysis_id: ID de l'analyse
            comments: Commentaires (optionnel)
            tags: Liste de tags (optionnel)
            favorite: Marquer comme favori (optionnel)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Vérifier si des métadonnées existent déjà
        cursor.execute('''
        SELECT id FROM analysis_meta WHERE analysis_id = ?
        ''', (analysis_id,))
        
        existing = cursor.fetchone()
        
        if existing:
            # Mettre à jour les métadonnées existantes
            if tags:
                tags_str = ",".join(tags)
            else:
                tags_str = None
                
            cursor.execute('''
            UPDATE analysis_meta
            SET comments = ?, tags = ?, favorite = ?
            WHERE analysis_id = ?
            ''', (comments, tags_str, favorite, analysis_id))
        else:
            # Créer de nouvelles métadonnées
            if tags:
                tags_str = ",".join(tags)
            else:
                tags_str = None
                
            cursor.execute('''
            INSERT INTO analysis_meta
            (analysis_id, comments, tags, favorite)
            VALUES (?, ?, ?, ?)
            ''', (analysis_id, comments, tags_str, favorite))
        
        conn.commit()
        conn.close()
    
    def export_analysis_to_json(self, analysis_id: int) -> str:
        """
        Exporte une analyse au format JSON.
        
        Args:
            analysis_id: ID de l'analyse à exporter
            
        Returns:
            Chaîne JSON contenant l'analyse complète
        """
        analysis = self.get_analysis_by_id(analysis_id)
        if not analysis:
            return "{}"
        
        return json.dumps(analysis, indent=2)
    
    def delete_analysis(self, analysis_id: int) -> bool:
        """
        Supprime une analyse et tous ses résultats associés.
        
        Args:
            analysis_id: ID de l'analyse à supprimer
            
        Returns:
            True si la suppression a réussi, False sinon
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Supprimer les métadonnées
            cursor.execute('DELETE FROM analysis_meta WHERE analysis_id = ?', (analysis_id,))
            
            # Supprimer les résultats de corrélation
            cursor.execute('DELETE FROM correlation_results WHERE analysis_id = ?', (analysis_id,))
            
            # Supprimer les résultats Vanir
            cursor.execute('DELETE FROM vanir_results WHERE analysis_id = ?', (analysis_id,))
            
            # Supprimer les résultats Joern
            cursor.execute('DELETE FROM joern_results WHERE analysis_id = ?', (analysis_id,))
            
            # Supprimer les résultats SBOM
            cursor.execute('DELETE FROM sbom_results WHERE analysis_id = ?', (analysis_id,))
            
            # Supprimer l'analyse elle-même
            cursor.execute('DELETE FROM analysis WHERE id = ?', (analysis_id,))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la suppression de l'analyse {analysis_id}: {str(e)}")
            return False
    
    def get_vulnerabilities_by_analysis(self, analysis_id: int) -> List[Dict]:
        """
        Récupère les vulnérabilités pour une analyse donnée.
        
        Args:
            analysis_id: ID de l'analyse
            
        Returns:
            Liste des vulnérabilités
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM vanir_results WHERE analysis_id = ?
        ''', (analysis_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return []
        
        raw_results = json.loads(row["raw_results"] if row["raw_results"] else "{}")
        vulnerabilities = raw_results.get("vulnerabilities", [])
        
        return vulnerabilities
    
    def get_correlations_by_analysis(self, analysis_id: int) -> List[Dict]:
        """
        Récupère les corrélations pour une analyse donnée.
        
        Args:
            analysis_id: ID de l'analyse
            
        Returns:
            Liste des corrélations
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM correlation_results WHERE analysis_id = ?
        ''', (analysis_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return []
        
        raw_results = json.loads(row["raw_results"] if row["raw_results"] else "{}")
        correlations = raw_results.get("correlations", [])
        
        return correlations
    
    def clear_analysis_history(self) -> bool:
        """
        Supprime toutes les analyses et leurs résultats associés.
        
        Returns:
            True si la suppression a réussi, False sinon
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Supprimer toutes les données dans l'ordre inverse des dépendances
            cursor.execute('DELETE FROM analysis_meta')
            cursor.execute('DELETE FROM correlation_results')
            cursor.execute('DELETE FROM vanir_results')
            cursor.execute('DELETE FROM joern_results')
            cursor.execute('DELETE FROM sbom_results')
            cursor.execute('DELETE FROM analysis')
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la suppression de l'historique: {str(e)}")
            return False


class AnalysisIntegration:
    """Intègre les outils d'analyse avec la base de données"""

    def __init__(self, db_path: str = None):
        """
        Initialise l'intégration des analyses.
        
        Args:
            db_path: Chemin vers la base de données (optionnel)
        """
        self.db = get_database(db_path)
        self.logger = logging.getLogger(self.__class__.__name__)

    def run_integrated_analysis(self, repo_path: str, scanner_type: str, 
                              progress_callback: Callable = None,
                              package_name: str = None, ecosystem: str = None) -> Dict:
        """
        Exécute une analyse intégrée (Vanir + Joern) et stocke les résultats dans la BD.
        
        Args:
            repo_path: Chemin du dépôt à analyser
            scanner_type: Type de scanner Vanir à utiliser
            progress_callback: Fonction de callback pour le suivi de progression
            package_name: Nom du package (pour scanner_type=package_scanner)
            ecosystem: Écosystème (pour scanner_type=package_scanner ou repo_scanner)
            
        Returns:
            Dictionnaire contenant les résultats et métadonnées de l'analyse
        """
        start_time = time.time()
        
        # 1. Créer une entrée d'analyse dans la BD
        analysis_id = self.db.create_analysis(
            repo_path=repo_path,
            analysis_type="integrated"
        )
        
        try:
            # 2. Initialiser l'agent de corrélation
            try:
                from correlation_engine import CorrelationAgent
            except ImportError:
                from correlation_engine.correlation_engine import CorrelationAgent
            agent = CorrelationAgent(progress_callback=progress_callback)
            
            # 3. Exécuter l'analyse
            if progress_callback:
                progress_callback("start", "Démarrage de l'analyse intégrée...", 0.1)
                
            report = agent.analyze_repository(
                repo_path=repo_path,
                scanner_type=scanner_type,
                package_name=package_name,
                ecosystem=ecosystem
            )
            
            if "error" in report:
                raise Exception(report["error"])
            
            # 4. Extraire les vulnérabilités Vanir et les résultats Joern
            vulnerabilities = []
            for correlation in report.get("correlations", []):
                vulnerabilities.append(correlation.get("vulnerability", {}))
            
            # Identifier les fonctions non utilisées
            unused_functions = []
            for correlation in report.get("correlations", []):
                if correlation.get("is_function_unused"):
                    vuln = correlation.get("vulnerability", {})
                    unused_functions.append({
                        "name": vuln.get("function_name", ""),
                        "file": vuln.get("file_path", ""),
                        "line": 0
                    })
            
            # 5. Sauvegarder les résultats Vanir dans la BD
            if progress_callback:
                progress_callback("vanir", "Enregistrement des résultats Vanir...", 0.7)
                
            summary = report.get("analysis_summary", {})
            vanir_id = self.db.save_vanir_results(
                analysis_id=analysis_id,
                vulnerabilities=vulnerabilities,
                summary={
                    "critical": summary.get("critical_count", 0),
                    "high": summary.get("high_count", 0),
                    "medium": summary.get("medium_count", 0),
                    "low": summary.get("low_count", 0)
                }
            )
            
            # 6. Sauvegarder les résultats Joern dans la BD
            if progress_callback:
                progress_callback("joern", "Enregistrement des résultats Joern...", 0.8)
                
            joern_id = self.db.save_joern_results(
                analysis_id=analysis_id,
                unused_functions=unused_functions
            )
            
            # 7. Sauvegarder les résultats de corrélation dans la BD
            if progress_callback:
                progress_callback("correlation", "Enregistrement des corrélations...", 0.9)
                
            self.db.save_correlation_results(
                analysis_id=analysis_id,
                vanir_id=vanir_id,
                joern_id=joern_id,
                correlations=[
                    {
                        "vulnerability": corr.get("vulnerability", {}),
                        "risk_level": corr.get("risk_level", ""),
                        "risk_explanation": corr.get("risk_explanation", ""),
                        "is_function_unused": corr.get("is_function_unused", False)
                    }
                    for corr in report.get("correlations", [])
                ]
            )
            
            # 8. Mettre à jour le statut de l'analyse
            duration_seconds = int(time.time() - start_time)
            self.db.update_analysis_status(
                analysis_id=analysis_id,
                status="completed",
                duration_seconds=duration_seconds
            )
            
            if progress_callback:
                progress_callback("complete", f"Analyse terminée en {duration_seconds} secondes", 1.0)
            
            # 9. Ajouter l'ID d'analyse au rapport
            report["analysis_id"] = analysis_id
            
            return report
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse intégrée: {str(e)}")
            
            # En cas d'erreur, mettre à jour le statut dans la BD
            self.db.update_analysis_status(
                analysis_id=analysis_id,
                status="failed"
            )
            
            return {
                "analysis_id": analysis_id,
                "error": str(e),
                "status": "failed"
            }

    def run_vanir_analysis(self, repo_path: str, scanner_type: str, 
                        progress_callback: Callable = None,
                        package_name: str = None, ecosystem: str = None,
                        vulnerability_files: List[str] = None) -> Dict:
        """
        Exécute une analyse Vanir uniquement et stocke les résultats dans la BD.
        
        Args:
            repo_path: Chemin du dépôt à analyser
            scanner_type: Type de scanner Vanir à utiliser
            progress_callback: Fonction de callback pour le suivi de progression
            package_name: Nom du package (pour scanner_type=package_scanner)
            ecosystem: Écosystème (pour scanner_type=package_scanner ou repo_scanner)
            vulnerability_files: Liste des fichiers de vulnérabilités (optionnel)
            
        Returns:
            Dictionnaire contenant les résultats et métadonnées de l'analyse
        """
        start_time = time.time()
        
        # 1. Créer une entrée d'analyse dans la BD
        analysis_id = self.db.create_analysis(
            repo_path=repo_path,
            analysis_type="vanir_only"
        )
        
        try:
            # 2. Initialiser l'agent de corrélation
            try:
                from correlation_engine import CorrelationAgent
            except ImportError:
                from correlation_engine.correlation_engine import CorrelationAgent
            agent = CorrelationAgent(progress_callback=progress_callback)
            
            # 3. Exécuter l'analyse Vanir
            if progress_callback:
                progress_callback("start", "Démarrage de l'analyse Vanir...", 0.1)
                
            report = agent.run_vanir_only_analysis(
                repo_path=repo_path,
                scanner_type=scanner_type,
                package_name=package_name,
                ecosystem=ecosystem,
                vulnerability_files=vulnerability_files
            )
            
            if "error" in report:
                raise Exception(report["error"])
            
            # 4. Extraire les vulnérabilités Vanir
            vulnerabilities = report.get("vulnerabilities", [])
            
            # 5. Sauvegarder les résultats Vanir dans la BD
            if progress_callback:
                progress_callback("saving", "Enregistrement des résultats...", 0.8)
                
            summary = report.get("analysis_summary", {})
            vanir_id = self.db.save_vanir_results(
                analysis_id=analysis_id,
                vulnerabilities=vulnerabilities,
                summary={
                    "critical": summary.get("critical_count", 0),
                    "high": summary.get("high_count", 0),
                    "medium": summary.get("medium_count", 0),
                    "low": summary.get("low_count", 0)
                }
            )
            
            # 6. Mettre à jour le statut de l'analyse
            duration_seconds = int(time.time() - start_time)
            self.db.update_analysis_status(
                analysis_id=analysis_id,
                status="completed",
                duration_seconds=duration_seconds
            )
            
            if progress_callback:
                progress_callback("complete", f"Analyse terminée en {duration_seconds} secondes", 1.0)
            
            return {
                "analysis_id": analysis_id,
                "status": "completed",
                "duration_seconds": duration_seconds,
                "vulnerabilities": vulnerabilities
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse Vanir: {str(e)}")
            
            # En cas d'erreur, mettre à jour le statut dans la BD
            self.db.update_analysis_status(
                analysis_id=analysis_id,
                status="failed"
            )
            
            return {
                "analysis_id": analysis_id,
                "status": "failed",
                "error": str(e)
            }

    def run_joern_analysis(self, repo_path: str, 
                         progress_callback: Callable = None) -> Dict:
        """
        Exécute une analyse Joern uniquement et stocke les résultats dans la BD.
        
        Args:
            repo_path: Chemin du dépôt à analyser
            progress_callback: Fonction de callback pour le suivi de progression
            
        Returns:
            Dictionnaire contenant les résultats et métadonnées de l'analyse
        """
        start_time = time.time()
        
        # 1. Créer une entrée d'analyse dans la BD
        analysis_id = self.db.create_analysis(
            repo_path=repo_path,
            analysis_type="joern_only"
        )
        
        try:
            # 2. Initialiser l'agent de corrélation (pour utiliser le JoernToolRunner)
            try:
                from correlation_engine import CorrelationAgent
            except ImportError:
                from correlation_engine.correlation_engine import CorrelationAgent
            agent = CorrelationAgent(progress_callback=progress_callback)
            
            # 3. Exécuter l'analyse Joern
            if progress_callback:
                progress_callback("start", "Démarrage de l'analyse Joern...", 0.1)
                
            joern_data = agent.joern_runner.run_analysis(repo_path)
            
            # 4. Parser les résultats
            if progress_callback:
                progress_callback("parsing", "Analyse des résultats...", 0.6)
                
            unused_functions = agent.joern_parser.parse(joern_data)
            
            # 5. Sauvegarder les résultats Joern dans la BD
            if progress_callback:
                progress_callback("saving", "Enregistrement des résultats...", 0.8)
                
            joern_id = self.db.save_joern_results(
                analysis_id=analysis_id,
                unused_functions=[vars(f) for f in unused_functions]
            )
            
            # 6. Mettre à jour le statut de l'analyse
            duration_seconds = int(time.time() - start_time)
            self.db.update_analysis_status(
                analysis_id=analysis_id,
                status="completed",
                duration_seconds=duration_seconds
            )
            
            if progress_callback:
                progress_callback("complete", f"Analyse terminée en {duration_seconds} secondes", 1.0)
            
            return {
                "analysis_id": analysis_id,
                "status": "completed",
                "duration_seconds": duration_seconds,
                "unused_functions": [vars(f) for f in unused_functions]
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse Joern: {str(e)}")
            
            # En cas d'erreur, mettre à jour le statut dans la BD
            self.db.update_analysis_status(
                analysis_id=analysis_id,
                status="failed"
            )
            
            return {
                "analysis_id": analysis_id,
                "status": "failed",
                "error": str(e)
            }

    def run_sbom_analysis(self, repo_path: str, sbom_file: str = None, 
                        progress_callback: Callable = None) -> Dict:
        """
        Exécute une analyse SBOM et stocke les résultats dans la BD.
        
        Args:
            repo_path: Chemin du dépôt à analyser
            sbom_file: Chemin vers un fichier SBOM existant (optionnel)
            progress_callback: Fonction de callback pour le suivi de progression
            
        Returns:
            Dictionnaire contenant les résultats et métadonnées de l'analyse
        """
        if not SBOM_AVAILABLE:
            return {
                "status": "failed",
                "error": "Module SBOM non disponible"
            }
            
        start_time = time.time()
        
        # 1. Créer une entrée d'analyse dans la BD
        analysis_id = self.db.create_analysis(
            repo_path=repo_path,
            analysis_type="sbom_only"
        )
        
        try:
            # 2. Initialiser l'analyseur SBOM
            analyzer = SBOMAnalyzer(callback=progress_callback)
            
            # 3. Exécuter l'analyse SBOM
            if progress_callback:
                progress_callback("start", "Démarrage de l'analyse SBOM...", 0.1)
                
            if sbom_file and os.path.exists(sbom_file):
                # Utiliser un fichier SBOM existant
                result = analyzer.analyze_sbom_file(sbom_file)
            else:
                # Générer un SBOM à partir du dépôt
                result = analyzer.analyze_repository(repo_path)
            
            # 4. Sauvegarder les résultats SBOM dans la BD
            if progress_callback:
                progress_callback("saving", "Enregistrement des résultats...", 0.8)
                
            sbom_id = self.db.save_sbom_results(
                analysis_id=analysis_id,
                sbom_data=result
            )
            
            # 5. Mettre à jour le statut de l'analyse
            duration_seconds = int(time.time() - start_time)
            self.db.update_analysis_status(
                analysis_id=analysis_id,
                status="completed",
                duration_seconds=duration_seconds
            )
            
            if progress_callback:
                progress_callback("complete", f"Analyse terminée en {duration_seconds} secondes", 1.0)
            
            return {
                "analysis_id": analysis_id,
                "status": "completed",
                "duration_seconds": duration_seconds,
                **result  # Inclure tous les résultats de l'analyseur
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse SBOM: {str(e)}")
            
            # En cas d'erreur, mettre à jour le statut dans la BD
            self.db.update_analysis_status(
                analysis_id=analysis_id,
                status="failed"
            )
            
            return {
                "analysis_id": analysis_id,
                "status": "failed",
                "error": str(e)
            }

    def run_file_based_analysis(self, vanir_file: str, joern_file: str, 
                              progress_callback: Callable = None) -> Dict:
        """
        Exécute une analyse à partir de fichiers de résultats existants.
        
        Args:
            vanir_file: Chemin vers le fichier de résultats Vanir
            joern_file: Chemin vers le fichier de résultats Joern
            progress_callback: Fonction de callback pour le suivi de progression
            
        Returns:
            Dictionnaire contenant les résultats et métadonnées de l'analyse
        """
        start_time = time.time()
        
        # 1. Créer une entrée d'analyse dans la BD
        analysis_id = self.db.create_analysis(
            repo_path="file_based",
            analysis_type="file_based"
        )
        
        try:
            # 2. Initialiser l'agent de corrélation
            try:
                from correlation_engine import CorrelationAgent
            except ImportError:
                from correlation_engine.correlation_engine import CorrelationAgent
            agent = CorrelationAgent(progress_callback=progress_callback)
            
            # 3. Charger et valider les fichiers d'entrée
            if progress_callback:
                progress_callback("loading", "Chargement des fichiers d'entrée...", 0.1)
                
            if not os.path.exists(vanir_file):
                raise FileNotFoundError(f"Fichier Vanir non trouvé: {vanir_file}")
                
            if not os.path.exists(joern_file):
                raise FileNotFoundError(f"Fichier Joern non trouvé: {joern_file}")
                
            # 4. Exécuter la corrélation à partir des fichiers
            if progress_callback:
                progress_callback("correlation", "Corrélation des résultats...", 0.4)
                
            report = agent.analyze_existing_files(
                vanir_results_path=vanir_file,
                joern_results_path=joern_file
            )
            
            if "error" in report:
                raise Exception(report["error"])
            
            # 5. Extraire les données pour la BD
            vulnerabilities = []
            for correlation in report.get("correlations", []):
                vulnerabilities.append(correlation.get("vulnerability", {}))
            
            unused_functions = []
            for correlation in report.get("correlations", []):
                if correlation.get("is_function_unused"):
                    vuln = correlation.get("vulnerability", {})
                    unused_functions.append({
                        "name": vuln.get("function_name", ""),
                        "file": vuln.get("file_path", ""),
                        "line": 0
                    })
            
            # 6. Sauvegarder les résultats dans la BD
            if progress_callback:
                progress_callback("saving", "Enregistrement des résultats...", 0.7)
                
            summary = report.get("analysis_summary", {})
            vanir_id = self.db.save_vanir_results(
                analysis_id=analysis_id,
                vulnerabilities=vulnerabilities,
                summary={
                    "critical": summary.get("critical_count", 0),
                    "high": summary.get("high_count", 0),
                    "medium": summary.get("medium_count", 0),
                    "low": summary.get("low_count", 0)
                }
            )
            
            joern_id = self.db.save_joern_results(
                analysis_id=analysis_id,
                unused_functions=unused_functions
            )
            
            self.db.save_correlation_results(
                analysis_id=analysis_id,
                vanir_id=vanir_id,
                joern_id=joern_id,
                correlations=[
                    {
                        "vulnerability": corr.get("vulnerability", {}),
                        "risk_level": corr.get("risk_level", ""),
                        "risk_explanation": corr.get("risk_explanation", ""),
                        "is_function_unused": corr.get("is_function_unused", False)
                    }
                    for corr in report.get("correlations", [])
                ]
            )
            
            # 7. Mettre à jour le statut de l'analyse
            duration_seconds = int(time.time() - start_time)
            self.db.update_analysis_status(
                analysis_id=analysis_id,
                status="completed",
                duration_seconds=duration_seconds
            )
            
            if progress_callback:
                progress_callback("complete", f"Analyse terminée en {duration_seconds} secondes", 1.0)
            
            report["analysis_id"] = analysis_id
            return report
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse basée sur des fichiers: {str(e)}")
            
            # En cas d'erreur, mettre à jour le statut dans la BD
            self.db.update_analysis_status(
                analysis_id=analysis_id,
                status="failed"
            )
            
            return {
                "analysis_id": analysis_id,
                "status": "failed",
                "error": str(e)
            }


def get_database(db_path: str = None) -> AnalysisDatabase:
    """
    Récupère ou crée une instance de la base de données (pattern Singleton).
    
    Args:
        db_path: Chemin vers le fichier de base de données (optionnel)
        
    Returns:
        Instance de AnalysisDatabase
    """
    # Calculer le chemin par défaut si nécessaire
    if db_path is None:
        # Current file is in tools/vulnerability_correlation/db_integration.py
        # We need to go up to tools/data/
        current_dir = os.path.dirname(os.path.abspath(__file__))  # tools/vulnerability_correlation
        tools_dir = os.path.dirname(current_dir)  # tools
        data_dir = os.path.join(tools_dir, "data")  # tools/data
        os.makedirs(data_dir, exist_ok=True)
        db_path = os.path.join(data_dir, "correlation_analysis.db")
    
    # Pour Streamlit, nous utilisons une approche différente pour éviter la réinitialisation
    # Utilisons le cache de session pour maintenir l'instance
    try:
        import streamlit as st
        # Initialiser le cache de session s'il n'existe pas
        if 'db_instances' not in st.session_state:
            st.session_state.db_instances = {}
        
        if db_path not in st.session_state.db_instances:
            st.session_state.db_instances[db_path] = AnalysisDatabase(db_path)
            logger.debug(f"Nouvelle instance de base de données créée pour: {db_path}")
        else:
            logger.debug(f"Instance existante de base de données réutilisée pour: {db_path}")
            
        return st.session_state.db_instances[db_path]
    except ImportError:
        # Fallback pour les environnements non-Streamlit
        if not hasattr(get_database, '_instances'):
            get_database._instances = {}
            
        if db_path not in get_database._instances:
            get_database._instances[db_path] = AnalysisDatabase(db_path)
            logger.debug(f"Nouvelle instance de base de données créée pour: {db_path}")
        else:
            logger.debug(f"Instance existante de base de données réutilisée pour: {db_path}")
            
        return get_database._instances[db_path]


if __name__ == "__main__":
    # Tests simples de la base de données et de l'intégration
    db = get_database()
    print(f"Base de données initialisée à : {db.db_path}")
    
    # Récupérer les statistiques (pour vérifier que tout fonctionne)
    stats = db.get_statistics()
    print("Statistiques de la base de données :")
    print(stats)
