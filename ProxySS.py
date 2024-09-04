import os
import time
import logging
import streamlit as st
import geoip2.database
import sqlite3
from datetime import datetime, timedelta
import asyncio
import aiohttp
from typing import Set, Dict, List
from tenacity import retry, stop_after_attempt, wait_exponential
from enum import IntEnum
from pathlib import Path
import json
import random
from aiohttp_socks import ProxyConnector
import requests

# Constants
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", 1000))
MAX_CONCURRENT_CHECKS = int(os.getenv("MAX_CONCURRENT_CHECKS", 1000))
DB_PATH = os.getenv("DB_PATH", "proxy_database.db")
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY", "your_default_key_here")
PROXY_TIMEOUT = 10  # Timeout in seconds for proxy checks

# GeoIP URLs
GEOIP_URLS = {
    "GeoLite2-City.mmdb": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
    "GeoLite2-ASN.mmdb": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
    "GeoLite2-Country.mmdb": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
}

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('proxy_scanner')

# Suppress asyncio debug logs
logging.getLogger('asyncio').setLevel(logging.WARNING)

# Proxy sources
PROXY_SOURCES = [
    "https://www.socks-proxy.net/",
    "https://www.proxynova.com/proxy-server-list/country-br/"
]

class AnonymityLevel(IntEnum):
    TRANSPARENT = 1
    ANONYMOUS = 2
    ELITE = 3


class ImprovedProxyScanner:
    def __init__(self):
        """Initialize the proxy scanner."""
        self.ensure_geoip_files()
        self.geoip_reader, self.isp_reader = self.initialize_geoip()
        self.chunk_size = CHUNK_SIZE
        self.max_concurrent_checks = MAX_CONCURRENT_CHECKS
        self.min_successful_checks = 2
        self.last_scan_time = None
        self.blacklisted_proxies = set()
        self.geoip_cache = {}
        self.verification_endpoints = [
            "http://ip-api.com/json/",
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/all.json",
            "https://ipinfo.io/json",
        ]

        self.db_conn = sqlite3.connect(DB_PATH)
        self.initialize_db()

    def ensure_geoip_files(self):
        """Ensure that all required GeoIP database files are present."""
        for file_name, url in GEOIP_URLS.items():
            self.download_geoip_db(file_name, url)

    @staticmethod
    def download_geoip_db(file_name: str, url: str):
        """Download a GeoIP database file if not already present."""
        file_path = Path(file_name)
        
        if not file_path.exists():
            try:
                response = requests.get(url, stream=True)
                response.raise_for_status()  # Check if the request was successful
                with open(file_name, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)
                logger.info(f"{file_name} downloaded successfully.")
            except requests.RequestException as e:
                logger.error(f"Failed to download {file_name}: {e}")
        else:
            logger.info(f"{file_name} already exists, skipping download.")

    def initialize_geoip(self):
        """Initialize the GeoIP database readers."""
        geoip_path = Path("GeoLite2-City.mmdb")
        isp_path = Path("GeoLite2-ASN.mmdb")

        try:
            geoip_reader = self._load_geoip_reader(geoip_path)
            isp_reader = self._load_geoip_reader(isp_path)
            return geoip_reader, isp_reader
        except Exception as e:
            logger.error(f"Error loading GeoIP databases: {e}")
            st.warning("An error occurred while loading the GeoIP databases.")
            return None, None

    @staticmethod
    def _load_geoip_reader(file_path: Path):
        """Load GeoIP database reader."""
        if file_path.exists() and file_path.stat().st_size > 1_000_000:
            logger.info(f"Successfully loaded {file_path}")
            return geoip2.database.Reader(file_path)
        raise ValueError(f"{file_path} file is too small or missing.")

    def initialize_db(self):
        """Initialize the SQLite database."""
        try:
            with self.db_conn as conn:
                c = conn.cursor()
                c.execute(
                    '''CREATE TABLE IF NOT EXISTS proxies (
                        proxy TEXT PRIMARY KEY, 
                        latency REAL, 
                        country TEXT, 
                        city TEXT,
                        last_checked TIMESTAMP, 
                        successful_checks INTEGER, 
                        total_checks INTEGER,
                        anonymity_level INTEGER, 
                        isp TEXT, 
                        protocols TEXT)'''
                )
                c.execute('CREATE INDEX IF NOT EXISTS idx_country ON proxies(country)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_latency ON proxies(latency)')
                c.execute('CREATE INDEX IF NOT EXISTS idx_anonymity ON proxies(anonymity_level)')
                conn.execute('PRAGMA synchronous = OFF')
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize the database: {e}")
            st.error("Failed to initialize the database. Please check the logs for more details.")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def fetch_proxies(self) -> Set[str]:
        """Fetch proxies from the provided sources."""
        proxies = set()
        async with aiohttp.ClientSession() as session:
            for url in PROXY_SOURCES:
                try:
                    async with session.get(url, timeout=30) as response:
                        if response.status == 200:
                            text = await response.text()
                            proxies.update(text.splitlines())
                            logger.info(f"Fetched {len(text.splitlines())} proxies from {url}")
                        else:
                            logger.warning(f"Failed to fetch proxies from {url} with status code {response.status}")
                except Exception as e:
                    logger.error(f"Error fetching from {url}: {e}")
        return proxies

    # Continue the rest of the methods...

    # Main method
    def main(self):
        """Main method to run the Streamlit app."""
        st.title("Improved Proxy Scanner")
        st.write("Choose an option:")
        option = st.selectbox("Options", ["Scan Proxies", "View Results", "Filter Proxies", "Export Proxies", "Refresh Data", "Blacklist Proxy", "Schedule Scan"])
        
        if option == "Scan Proxies":
            self.run_scan()
        elif option == "View Results":
            self.view_results()
        elif option == "Filter Proxies":
            self.filter_proxies()
        elif option == "Export Proxies":
            self.export_proxies()
        elif option == "Refresh Data":
            self.refresh_data()
        elif option == "Blacklist Proxy":
            proxy_to_blacklist = st.text_input("Enter proxy to blacklist:")
            if proxy_to_blacklist:
                self.blacklist_proxy(proxy_to_blacklist)
        elif option == "Schedule Scan":
            scan_interval = st.selectbox("Select scan interval:", ["daily", "weekly"])
            self.schedule_scan(scan_interval)

        self.display_proxy_count()
       
