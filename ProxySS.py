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
import enum
import schedule
import threading
import json
import random
from aiohttp_socks import ProxyConnector

# Constants
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", 1000))
MAX_CONCURRENT_CHECKS = int(os.getenv("MAX_CONCURRENT_CHECKS", 1000))
DB_PATH = os.getenv("DB_PATH", "proxy_database.db")
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY", "your_default_key_here")
# Proxy sources
PROXY_SOURCES = [
    "https://www.socks-proxy.net/",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt",
    "https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt",
    "https://raw.githubusercontent.com/ArrayIterator/proxy-lists/main/proxies/all.txt",
    "https://raw.githubusercontent.com/system-organizer/free-proxy-list/main/raw-list.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
    "https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_geolocation_anonymous/http.txt",
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://raw.githubusercontent.com/a2u/free-proxy-list/master/free-proxy-list.txt",
    "https://github.com/mmpx12/proxy-list/blob/master/proxies.txt",
    "https://github.com/MuRongPIG/Proxy-Master/blob/main/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://www.sslproxies.org/",
    "https://www.freeproxy.world/",
    "https://free-proxy-list.net/",
    "https://www.us-proxy.org/",
    "https://free-proxy-list.net/uk-proxy.html",
    "https://www.socks-proxy.net/",
    "https://yakumo.rei.my.id/ALL",
    "https://yakumo.rei.my.id/pALL",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/archive/txt/proxies.txt",
    "https://www.proxy-list.download/api/v1/get?type=socks4",
    "https://www.proxy-list.download/api/v1/get?type=socks5",
    "https://proxy-daily.com/",
    "https://www.proxy-list.download/api/v1/get?type=https",
    "https://www.proxy-list.download/api/v1/get?type=socks",
    "https://api.proxyscrape.com/?request=getproxies&proxytype=http",
    "https://api.proxyscrape.com/?request=getproxies&proxytype=socks4",
    "https://api.proxyscrape.com/?request=getproxies&proxytype=socks5",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://www.my-proxy.com/free-proxy-list.html",
    "https://www.my-proxy.com/free-proxy-list.html",
    "https://www.sslproxies.org/",
    "https://free-proxy-list.net/",
    "https://www.us-proxy.org/",
    "https://free-proxy-list.net/uk-proxy.html",
    "https://free-proxy-list.net/anonymous-proxy.html",
    "https://www.socks-proxy.net/",
    "https://www.sslproxies.org/",
    "https://www.proxynova.com/proxy-server-list/",
    "https://www.cool-proxy.net/proxies/http_proxy_list/sort:score/direction:desc",
    "https://www.proxy-listen.de/Proxy/Proxyliste.html",
    "https://www.proxy-listen.de/Proxy/Proxyliste.html?filter_port=&filter_http_gateway=1&filter_http_anon=1&filter_http_anonelite=1&country=us",
    "https://free-proxy-list.net/elite-proxy.html",
    "https://free-proxy-list.net/anonymous-proxy.html",
    "https://www.proxynova.com/proxy-server-list/country-us/",
    "https://www.proxynova.com/proxy-server-list/country-ca/",
    "https://www.proxynova.com/proxy-server-list/country-gb/",
    "https://www.proxynova.com/proxy-server-list/country-de/",
    "https://www.proxynova.com/proxy-server-list/country-fr/",
    "https://www.proxynova.com/proxy-server-list/country-jp/",
    "https://www.proxynova.com/proxy-server-list/country-ru/",
    "https://www.proxynova.com/proxy-server-list/country-br/"
]
PROXY_TIMEOUT = 10  # Timeout in seconds for proxy checks

# Set up logging
logger = logging.getLogger('proxy_scanner')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Suppress asyncio debug logs
logging.getLogger('asyncio').setLevel(logging.WARNING)

class AnonymityLevel(enum.IntEnum):
    TRANSPARENT = 1
    ANONYMOUS = 2
    ELITE = 3

class ImprovedProxyScanner:
    def __init__(self):
        """Initialize the proxy scanner."""
        self.geoip_reader, self.isp_reader = self.initialize_geoip()
        self.chunk_size = CHUNK_SIZE
        self.max_concurrent_checks = MAX_CONCURRENT_CHECKS
        self.min_successful_checks = 2
        self.last_scan_time = None
        self.blacklisted_proxies = set()
        self.db_conn = sqlite3.connect(DB_PATH)
        self.initialize_db()
        self.geoip_cache = {}
        self.verification_endpoints = [
            "http://ip-api.com/json/",
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/all.json",
            "https://ipinfo.io/json",
        ]

    def initialize_geoip(self):
        """Initialize the GeoIP database readers."""
        geoip_path = "GeoLite2-City.mmdb"
        isp_path = "GeoLite2-ASN.mmdb"

        try:
            if os.path.exists(geoip_path) and os.path.getsize(geoip_path) > 1_000_000:
                geoip_reader = geoip2.database.Reader(geoip_path)
                logger.info(f"Successfully loaded {geoip_path}")
            else:
                raise ValueError(f"{geoip_path} file is too small or missing.")

            if os.path.exists(isp_path) and os.path.getsize(isp_path) > 1_000_000:
                isp_reader = geoip2.database.Reader(isp_path)
                logger.info(f"Successfully loaded {isp_path}")
            else:
                raise ValueError(f"{isp_path} file is too small or missing.")

            return geoip_reader, isp_reader
        except Exception as e:
            logger.error(f"Error loading GeoIP databases: {e}")
            st.warning("An error occurred while loading the GeoIP databases.")
            return None, None

    def initialize_db(self):
        """Initialize the SQLite database."""
        try:
            with self.db_conn:
                c = self.db_conn.cursor()
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

                self.db_conn.execute('PRAGMA synchronous = OFF')
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
                    # Continue to the next source
        return proxies

    async def quick_protocol_check(self, proxy: str) -> List[str]:
        """Quickly check which protocols a proxy supports."""
        supported_protocols = []
        timeout = aiohttp.ClientTimeout(total=5)

        protocols = {
            'http': {'url': 'http://example.com', 'connector': None},
            'https': {'url': 'https://example.com', 'connector': None},
            'socks4': {'url': 'http://example.com', 'connector': ProxyConnector.from_url(f'socks4://{proxy}')},
            'socks5': {'url': 'http://example.com', 'connector': ProxyConnector.from_url(f'socks5://{proxy}')}
        }

        for protocol, config in protocols.items():
            try:
                async with aiohttp.ClientSession(connector=config['connector'], timeout=timeout) as session:
                    async with session.get(config['url'], proxy=f"{protocol}://{proxy}") as response:
                        if response.status == 200:
                            supported_protocols.append(protocol)
            except Exception as e:
                logger.debug(f"Protocol {protocol} not supported for proxy {proxy}: {str(e)}")

        return supported_protocols

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=5, max=20))
    async def check_proxy(self, proxy: str) -> Dict[str, any]:
        """Check the functionality of a proxy."""
        connector = aiohttp.TCPConnector(limit_per_host=100)
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                start_time = time.time()
                endpoint = random.choice(self.verification_endpoints)
                async with session.get(endpoint, proxy=f"http://{proxy}", timeout=PROXY_TIMEOUT) as response:
                    if response.status == 200:
                        data = await response.json()
                        ip = data.get('ip') or data.get('query')
                        latency = time.time() - start_time
                        geo_info = self.geoip_lookup(ip)
                        anonymity_level = await self.check_anonymity_level(proxy)
                        protocols = await self.quick_protocol_check(proxy)
                        logger.info(f"Proxy {proxy} passed with latency {latency:.2f} seconds, protocols: {protocols}")
                        return {
                            'proxy': proxy,
                            'latency': latency,
                            'ip': ip,
                            'country': geo_info['country'],
                            'city': geo_info['city'],
                            'isp': geo_info['isp'],
                            'anonymity_level': anonymity_level,
                            'protocols': protocols
                        }
                    else:
                        logger.warning(f"Proxy {proxy} failed with status code {response.status}")
            except Exception as e:
                logger.debug(f"Proxy {proxy} failed: {e}")
        return None

    async def check_anonymity_level(self, proxy: str) -> AnonymityLevel:
        """Check the anonymity level of a proxy."""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get("http://httpbin.org/headers", proxy=f"http://{proxy}", timeout=5) as response:
                    if response.status == 200:
                        headers = await response.json()
                        if 'X-Forwarded-For' not in headers['headers']:
                            return AnonymityLevel.ELITE
                        elif proxy.split(':')[0] not in headers['headers'].get('X-Forwarded-For', ''):
                            return AnonymityLevel.ANONYMOUS
                        else:
                            return AnonymityLevel.TRANSPARENT
            except Exception:
                pass
        return AnonymityLevel.TRANSPARENT

    async def scan_proxies(self, proxies: Set[str], progress_bar=None) -> List[Dict[str, any]]:
        """Scan a set of proxies to determine their functionality."""
        results = []
        total_proxies = len(proxies)
        valid_proxies = 0
        chunks = [list(proxies)[i:i + self.chunk_size] for i in range(0, total_proxies, self.chunk_size)]

        for index, chunk in enumerate(chunks):
            sem = asyncio.BoundedSemaphore(self.max_concurrent_checks)
            
            async def sem_check_proxy(proxy):
                async with sem:
                    return await self.check_proxy(proxy)

            tasks = [sem_check_proxy(proxy) for proxy in chunk]
            chunk_results = await asyncio.gather(*tasks)
            valid_chunk_results = [r for r in chunk_results if r and r['proxy'] not in self.blacklisted_proxies]
            valid_proxies += len(valid_chunk_results)
            
            # Update the progress bar
            if progress_bar:
                progress_bar.progress((index + 1) / len(chunks))
                
            logger.info(f"Processed chunk {index + 1}/{len(chunks)}: {len(valid_chunk_results)} valid proxies")
            results.extend(valid_chunk_results)

        self.last_scan_time = datetime.now()
        logger.info(f"Finished scanning {len(proxies)} proxies. Valid proxies found: {len(results)}")
        return results

    def geoip_lookup(self, ip: str) -> Dict[str, str]:
        """Lookup GeoIP information for a given IP address."""
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]

        if not self.geoip_reader or not self.isp_reader:
            return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}
        try:
            city_response = self.geoip_reader.city(ip)
            isp_response = self.isp_reader.asn(ip)
            geo_info = {
                'country': city_response.country.name or 'Unknown',
                'city': city_response.city.name or 'Unknown',
                'isp': isp_response.autonomous_system_organization or 'Unknown'
            }
            self.geoip_cache[ip] = geo_info
            return geo_info
        except Exception:
            logger.error(f"GeoIP lookup failed for IP: {ip}")
            return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}

    def update_proxy_database(self, proxy_data: Dict[str, any]):
        """Update the proxy database with scan results."""
        try:
            with self.db_conn:
                c = self.db_conn.cursor()
                c.execute(
                    '''INSERT OR REPLACE INTO proxies (
                        proxy, latency, country, city, last_checked, 
                        successful_checks, total_checks, anonymity_level, isp, protocols) 
                        VALUES (?, ?, ?, ?, ?,
                                COALESCE((SELECT successful_checks FROM proxies WHERE proxy = ?) + 1, 1),
                                COALESCE((SELECT total_checks FROM proxies WHERE proxy = ?) + 1, 1),
                                ?, ?, ?)''',
                    (
                        proxy_data['proxy'],
                        proxy_data.get('latency', 0),
                        proxy_data.get('country', 'Unknown'),
                        proxy_data.get('city', 'Unknown'),
                        datetime.now().isoformat(),
                        proxy_data['proxy'],
                        proxy_data['proxy'],
                        proxy_data.get('anonymity_level', AnonymityLevel.TRANSPARENT.value),
                        proxy_data.get('isp', 'Unknown'),
                        ','.join(proxy_data.get('protocols', []))
                    )
                )
                logger.info(f"Updated database with proxy: {proxy_data['proxy']}")
        except sqlite3.Error as e:
            logger.error(f"An error occurred while updating the database: {e}")
            logger.error(f"Proxy data: {proxy_data}")
        except KeyError as e:
            logger.error(f"Missing key in proxy data: {e}")
            logger.error(f"Proxy data: {proxy_data}")

    def get_filtered_proxies(self, country: str = None, max_latency: float = None,
                             min_anonymity: AnonymityLevel = None, protocols: List[str] = None) -> List[Dict[str, any]]:
        """Filter proxies based on the given criteria."""
        c = self.db_conn.cursor()
        query = '''SELECT * FROM proxies WHERE successful_checks >= ? AND last_checked >= ?'''
        params = [self.min_successful_checks, (datetime.now() - timedelta(days=7)).isoformat()]

        if country:
            query += ' AND country = ?'
            params.append(country)

        if max_latency:
            query += ' AND latency <= ?'
            params.append(max_latency)

        if min_anonymity:
            query += ' AND anonymity_level >= ?'
            params.append(min_anonymity.value)

        if protocols:
            query += ' AND (' + ' OR '.join(['protocols LIKE ?' for _ in protocols]) + ')'
            params.extend([f'%{p}%' for p in protocols])

        query += ' ORDER BY (successful_checks * 1.0 / total_checks) DESC, latency ASC'

        c.execute(query, params)
        return [dict(zip([column[0] for column in c.description], row)) for row in c.fetchall()]

    def run_scan(self):
        """Run the proxy scan process."""
        st.write("Starting proxy scanner...")
        try:
            proxies = asyncio.run(self.fetch_proxies())
        except Exception as e:
            st.error(f"Failed to fetch proxies: {e}")
            logger.error(f"Failed to fetch proxies: {e}")
            return

        total_proxies = len(proxies)
        st.write(f"Total proxies fetched: {total_proxies}")
        logger.info(f"Total proxies fetched: {total_proxies}")

        progress_bar = st.progress(0)

        try:
            results = asyncio.run(self.scan_proxies(proxies, progress_bar=progress_bar))
        except Exception as e:
            st.error(f"Error during proxy scanning: {e}")
            logger.error(f"Error during proxy scanning: {e}")
            return

        for result in results:
            try:
                self.update_proxy_database(result)
            except Exception as e:
                logger.error(f"Error updating database for proxy {result.get('proxy', 'Unknown')}: {e}")

        st.write("Scan complete!")
        logger.info("Proxy scan complete")
        if results:
            st.json(results)
        else:
            st.write("No valid proxies found.")

    def view_results(self):
        """View the best proxies from the database."""
        best_proxies = self.get_filtered_proxies()
        if best_proxies:
            st.write("Best proxies:")
            st.json(best_proxies)
        else:
            st.write("No proxies found in the database.")

    def filter_proxies(self):
        """Filter proxies based on user-defined criteria."""
        country = st.text_input("Enter country (leave blank for any):").strip() or None
        max_latency = st.number_input("Enter maximum latency in seconds (leave blank for any):", min_value=0.0) or None
        min_anonymity = st.selectbox("Enter minimum anonymity level (1-3, leave blank for any):", options=[1, 2, 3]) or None
        protocols = st.multiselect("Select required protocols:", options=["http", "https", "socks4", "socks5"])
        filtered_proxies = self.get_filtered_proxies(
            country=country,
            max_latency=max_latency,
            min_anonymity=AnonymityLevel(min_anonymity) if min_anonymity else None,
            protocols=protocols
        )
        if filtered_proxies:
            st.write("Filtered proxies:")
            st.json(filtered_proxies)
        else:
            st.write("No proxies match the filter criteria.")

    def export_proxies(self):
        """Export filtered proxies to a JSON file."""
        filename = st.text_input("Enter the export filename (default: filtered_proxies.json):") or "filtered_proxies.json"
        filtered_proxies = self.get_filtered_proxies()
        try:
            with open(filename, 'w') as f:
                json.dump(filtered_proxies, f, indent=2)
            st.write(f"Proxies successfully exported to {filename}")
            logger.info(f"Proxies exported to {filename}")
        except Exception as e:
            logger.error(f"Failed to export proxies: {e}")
            st.write(f"Failed to export proxies to {filename}")

    def display_proxy_count(self):
        """Display the total number of proxies in the database."""
        c = self.db_conn.cursor()
        c.execute("SELECT COUNT(*) FROM proxies")
        count = c.fetchone()[0]
        st.write(f"Total proxies in the database: {count}")

    def display_last_scan_time(self):
        """Display the last time a scan was run."""
        if self.last_scan_time:
            st.write(f"Last scan time: {self.last_scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            st.write("No scans have been performed yet.")

    def refresh_data(self):
        """Refresh the displayed data."""
        st.write("Refreshing data...")
        self.display_proxy_count()
        self.display_last_scan_time()
        st.write("Data refreshed.")

    def blacklist_proxy(self, proxy: str):
        """Add a proxy to the blacklist."""
        self.blacklisted_proxies.add(proxy)
        st.write(f"Proxy {proxy} has been blacklisted.")
        logger.info(f"Proxy {proxy} has been blacklisted.")

    def schedule_scan(self, interval: str = "daily"):
        """Schedule regular proxy scans."""
        def run_scheduled_scan():
            while True:
                schedule.run_pending()
                time.sleep(1)

        if interval == "daily":
            schedule.every().day.at("00:00").do(self.run_scan)
        elif interval == "weekly":
            schedule.every().monday.at("00:00").do(self.run_scan)

        thread = threading.Thread(target=run_scheduled_scan)
        thread.start()
        logger.info(f"Scheduled scans set to run {interval}")

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
        self.display_last_scan_time()

if __name__ == "__main__":
    scanner = ImprovedProxyScanner()
    scanner.main()
