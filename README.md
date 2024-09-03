# ProxyMaster-Lite: Advanced Proxy Scanner and Manager

## Overview

The `ImprovedProxyScanner` class is designed to scan, verify, and manage a list of proxies. It uses GeoIP databases to gather information about the proxies and stores the results in an SQLite database. The scanner can be run manually or scheduled to run at regular intervals.

## Table of Contents
- [Classes and Enums](#classes-and-enums)
  - [AnonymityLevel](#anonymitylevel)
  - [ImprovedProxyScanner](#improvedproxyscanner)
- [Methods](#methods)
  - [initialize_geoip](#initialize_geoip)
  - [initialize_db](#initialize_db)
  - [fetch_proxies](#fetch_proxies)
  - [quick_protocol_check](#quick_protocol_check)
  - [check_proxy](#check_proxy)
  - [check_anonymity_level](#check_anonymity_level)
  - [scan_proxies](#scan_proxies)
  - [geoip_lookup](#geoip_lookup)
  - [update_proxy_database](#update_proxy_database)
  - [get_filtered_proxies](#get_filtered_proxies)
  - [run_scan](#run_scan)
  - [view_results](#view_results)
  - [filter_proxies](#filter_proxies)
  - [export_proxies](#export_proxies)
  - [display_proxy_count](#display_proxy_count)
  - [display_last_scan_time](#display_last_scan_time)
  - [refresh_data](#refresh_data)
  - [blacklist_proxy](#blacklist_proxy)
  - [schedule_scan](#schedule_scan)
  - [main](#main)

---

## Classes and Enums

### AnonymityLevel

Enum representing the anonymity level of a proxy.

- **TRANSPARENT**: The proxy reveals the client's IP address.
- **ANONYMOUS**: The proxy does not reveal the client's IP address but does not hide its presence as a proxy.
- **ELITE**: The proxy hides both the client's IP address and its presence as a proxy.

### ImprovedProxyScanner

A class to scan, verify, and manage a list of proxies.

## Methods

### `initialize_geoip`

Initializes the GeoIP database readers.

**Returns:**
- `tuple`: A tuple containing the city and ISP GeoIP readers.

### `initialize_db`

Initializes the SQLite database, creating necessary tables and indexes.

### `fetch_proxies`

Fetches proxies from the provided sources.

**Returns:**
- `Set[str]`: A set of proxies fetched from the sources.

### `quick_protocol_check`

Quickly checks which protocols a proxy supports.

**Parameters:**
- `proxy (str)`: The proxy address to check.

**Returns:**
- `List[str]`: A list of supported protocols.

### `check_proxy`

Checks the functionality of a proxy.

**Parameters:**
- `proxy (str)`: The proxy address to check.

**Returns:**
- `Dict[str, any]`: A dictionary with the results of the proxy check.

### `check_anonymity_level`

Checks the anonymity level of a proxy.

**Parameters:**
- `proxy (str)`: The proxy address to check.

**Returns:**
- `AnonymityLevel`: The anonymity level of the proxy.

### `scan_proxies`

Scans a set of proxies to determine their functionality.

**Parameters:**
- `proxies (Set[str])`: A set of proxies to scan.
- `progress_bar`: A progress bar to update during the scan (optional).

**Returns:**
- `List[Dict[str, any]]`: A list of dictionaries with the results of the proxy checks.

### `geoip_lookup`

Looks up GeoIP information for a given IP address.

**Parameters:**
- `ip (str)`: The IP address to look up.

**Returns:**
- `Dict[str, str]`: A dictionary containing the country, city, and ISP of the IP address.

### `update_proxy_database`

Updates the proxy database with scan results.

**Parameters:**
- `proxy_data (Dict[str, any])`: A dictionary containing the proxy scan results.

### `get_filtered_proxies`

Filters proxies based on the given criteria.

**Parameters:**
- `country (str, optional)`: The country to filter by.
- `max_latency (float, optional)`: The maximum latency to filter by.
- `min_anonymity (AnonymityLevel, optional)`: The minimum anonymity level to filter by.
- `protocols (List[str], optional)`: The protocols to filter by.

**Returns:**
- `List[Dict[str, any]]`: A list of dictionaries containing the filtered proxies.

### `run_scan`

Runs the proxy scan process.

### `view_results`

Views the best proxies from the database.

### `filter_proxies`

Filters proxies based on user-defined criteria.

### `export_proxies`

Exports filtered proxies to a JSON file.

### `display_proxy_count`

Displays the total number of proxies in the database.

### `display_last_scan_time`

Displays the last time a scan was run.

### `refresh_data`

Refreshes the displayed data.

### `blacklist_proxy`

Adds a proxy to the blacklist.

**Parameters:**
- `proxy (str)`: The proxy address to blacklist.

### `schedule_scan`

Schedules regular proxy scans. *Not setup - Easy refactor"*

**Parameters:**
- `interval (str, optional)`: The interval at which to run the scans. Defaults to "daily".

### `main`

The main method to run the Streamlit app.

---

## Usage

1. **Scan Proxies**: Run the proxy scanner to fetch and verify proxies.
2. **View Results**: View the best proxies from the database.
3. **Filter Proxies**: Filter proxies based on custom criteria.
4. **Export Proxies**: Export filtered proxies to a JSON file.
5. **Refresh Data**: Refresh the displayed data.
6. **Blacklist Proxy**: Add a proxy to the blacklist.
7. **Schedule Scan**: Schedule proxy scans to run at regular intervals.

