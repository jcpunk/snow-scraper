#!/usr/bin/env python3
"""
ServiceNow CMDB Tree Explorer

This script builds a hierarchical tree of Configuration Items (CIs) from ServiceNow's CMDB
using containment relationships. It efficiently batches API calls, resolves DNS records,
and outputs a JSON tree structure with IP address resolution.

Key Features:
- Optimized batching to minimize API calls and avoid URL length limits
- Asynchronous DNS record retrieval and IP address resolution
- Cycle detection during tree traversal
- Comprehensive error handling with retries
- Inactive CI filtering
- Performance statistics tracking

The tree structure represents parent-child containment relationships where each node
can contain other CIs (e.g., a server room contains racks, which contain servers).
"""

import argparse
import asyncio
import json
import logging
import os
import pprint
import sys
import threading
import time

from collections import defaultdict, deque
from urllib.parse import urlencode

import aiodns
import requests

from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# ServiceNow API Configuration
RELATIONSHIP_SYS_ID = ["55c95bf6c0a8010e0118ec7056ebc54d"]  # Contained by
DEFAULT_BATCH_SIZE = 50
MAX_RETRIES = 3
RETRY_DELAY = 2
REQUEST_TIMEOUT = 30
MAX_URL_LENGTH = 8000  # Conservative limit to avoid 414 URI Too Long errors


class ServiceNowAPIError(Exception):
    """Custom exception for ServiceNow API-related errors."""

    pass


class ServiceNowCMDBExplorer:
    """
    ServiceNow CMDB explorer that builds containment trees efficiently.

    This class handles all interactions with the ServiceNow API, including:
    - CI relationship queries with intelligent batching
    - DNS record retrieval and IP resolution (async only)
    - Connection validation and error handling
    - Performance optimization through batch processing
    """

    def __init__(self, instance, username, password, batch_size=DEFAULT_BATCH_SIZE):
        """
        Initialize the CMDB explorer.

        Args:
            instance (str): ServiceNow instance domain (e.g., 'company.service-now.com')
            username (str): API username
            password (str): API password
            batch_size (int): Default batch size for API requests
        """
        self.logger = logging.getLogger(__name__)
        self.instance = instance
        self.batch_size = batch_size
        self.base_url = f"https://{instance}/api/now/table"

        self.async_resolver = aiodns.DNSResolver()
        self.logger.debug("Using aiodns for asynchronous DNS resolution")

        # Configure HTTP session with authentication and headers
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": f"ServiceNow-CMDB-Explorer/{username}",
            }
        )

        # Statistics tracking
        self.stats = defaultdict(int)
        self._stats_lock = threading.Lock()

    def _print_stats(self):
        """Print comprehensive API usage and performance statistics."""
        self.logger.info("=== API Usage Statistics ===")
        for key, value in sorted(self.stats.items(), key=lambda item: item[0]):
            self.logger.info(f"{key.replace('_', ' ').title()}: {value}")
        self.logger.info("=============================")

    def _generate_links(self, sys_id, table="cmdb_ci"):
        """
        Generate both API and UI links for a CI.

        Args:
            sys_id (str): ServiceNow sys_id of the CI
            table (str): Table name (default: cmdb_ci)

        Returns:
            dict: Contains 'api_link' and 'ui_link' keys
        """
        return {
            "api_link": f"https://{self.instance}/api/now/table/{table}/{sys_id}",
            "ui_link": f"https://{self.instance}/nav_to.do?uri={table}.do?sys_id={sys_id}",
        }

    def _estimate_batch_size(self, sys_ids):
        """
        Calculate optimal batch size to avoid URL length limits.

        ServiceNow has practical URL length limits. This method estimates how many
        sys_ids can fit in a single request based on average ID length.

        Args:
            sys_ids (list): List of sys_id strings

        Returns:
            int: Optimal batch size for this set of IDs
        """
        if not sys_ids:
            return self.batch_size

        avg_id_length = sum(len(sid) for sid in sys_ids) / len(sys_ids)
        base_overhead = 200  # Conservative estimate for base URL + parameter overhead
        max_ids = (MAX_URL_LENGTH - base_overhead) // (avg_id_length + 1)

        # Use 80% of calculated max for safety margin
        return min(self.batch_size, max(1, int(max_ids * 0.8)))

    def _make_api_request(self, url, params, max_retries=MAX_RETRIES):
        """
        Execute HTTP request with comprehensive error handling and retry logic.

        Handles common issues like:
        - Rate limiting (429 responses)
        - Network timeouts
        - Temporary service unavailability
        - Malformed responses

        Args:
            url (str): API endpoint URL
            params (dict): Query parameters
            max_retries (int): Number of retry attempts

        Returns:
            list: JSON response 'result' array

        Raises:
            ServiceNowAPIError: On persistent failures or invalid responses
        """
        for attempt in range(max_retries + 1):
            try:
                with self._stats_lock:
                    self.stats["api_calls"] += 1

                # Warn about potentially problematic URL lengths
                full_url = f"{url}?{urlencode(params)}"
                if len(full_url) > MAX_URL_LENGTH:
                    self.logger.warning(f"URL length ({len(full_url)}) may exceed limits")

                response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)

                # Handle rate limiting with proper backoff
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", RETRY_DELAY * (attempt + 1)))
                    self.logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                result = response.json()

                # Validate response structure
                if "result" not in result:
                    raise ServiceNowAPIError("Invalid response format: missing 'result' key")

                with self._stats_lock:
                    self.stats["total_records"] += len(result["result"])
                return result["result"]

            except requests.exceptions.Timeout:
                if attempt < max_retries:
                    self._handle_retry(attempt, "Request timeout")
                    continue
                raise ServiceNowAPIError(f"Request timeout after {max_retries + 1} attempts")

            except requests.exceptions.RequestException as e:
                if attempt < max_retries:
                    self._handle_retry(attempt, f"Request failed: {e}")
                    continue
                with self._stats_lock:
                    self.stats["failed_requests"] += 1
                raise ServiceNowAPIError(f"Request failed after {max_retries + 1} attempts: {e}")

        raise ServiceNowAPIError("Maximum retries exceeded")

    def _handle_retry(self, attempt, reason):
        """
        Handle retry logic with exponential backoff.

        Args:
            attempt (int): Current attempt number
            reason (str): Reason for retry
        """
        with self._stats_lock:
            self.stats["retries"] += 1
        delay = RETRY_DELAY * (attempt + 1)
        self.logger.warning(f"{reason}. Retrying in {delay} seconds...")
        time.sleep(delay)

    def _build_query(self, base_query, include_inactive=False):
        """
        Build ServiceNow query string with optional filtering.

        Args:
            base_query (str): Base query string
            include_inactive (bool): Whether to include inactive records

        Returns:
            str: Complete query string with filters applied
        """
        query_parts = [base_query]

        if not include_inactive:
            # Filter out inactive CIs in relationships
            query_parts.extend(["parent.u_active=true", "child.u_active=true"])

        return "^".join(query_parts)

    def _batch_api_call(self, endpoint, sys_ids, query_template, fields, include_inactive=False, limit_per_id=10):
        """
        Generic method for batched API calls with fallback to individual requests.

        This consolidates the common pattern used across multiple methods:
        1. Try batched request with IN operator
        2. Fall back to individual requests on failure
        3. Handle errors gracefully

        Args:
            endpoint (str): API endpoint (e.g., 'cmdb_rel_ci')
            sys_ids (list): List of sys_id values
            query_template (str): Query template with {} placeholder for sys_ids
            fields (str): Comma-separated field list
            include_inactive (bool): Include inactive records
            limit_per_id (int): Estimated records per sys_id for limit calculation

        Returns:
            list: Combined results from all requests
        """
        if not sys_ids:
            return []

        all_results = []
        batch_size = self._estimate_batch_size(sys_ids)

        self.logger.debug(f"Processing {len(sys_ids)} sys_ids with batch size {batch_size}")

        for i in range(0, len(sys_ids), batch_size):
            batch = sys_ids[i : i + batch_size]
            self.logger.debug(f"Processing batch {i//batch_size + 1}: {len(batch)} items")

            try:
                # Try batched query first
                query = query_template.format(",".join(batch))
                if not include_inactive and "u_active" not in query:
                    query += "^u_active=true"

                params = {
                    "sysparm_query": query,
                    "sysparm_fields": fields,
                    "sysparm_limit": str(len(batch) * limit_per_id),
                    "sysparm_display_value": "false",
                }

                results = self._make_api_request(f"{self.base_url}/{endpoint}", params)
                all_results.extend(results)
                self.logger.debug(f"Batched query returned {len(results)} records")

            except ServiceNowAPIError as e:
                self.logger.warning(f"Batched query failed: {e}. Using individual queries")

                # Fallback to individual queries
                for sys_id in batch:
                    try:
                        individual_query = query_template.format(sys_id)
                        if not include_inactive and "u_active" not in individual_query:
                            individual_query += "^u_active=true"

                        params = {
                            "sysparm_query": individual_query,
                            "sysparm_fields": fields,
                            "sysparm_limit": str(limit_per_id),
                            "sysparm_display_value": "false",
                        }

                        results = self._make_api_request(f"{self.base_url}/{endpoint}", params, max_retries=1)
                        all_results.extend(results)

                    except ServiceNowAPIError as e:
                        self.logger.debug(f"Individual query failed for {sys_id}: {e}")
                        continue

        return all_results

    async def _resolve_dns_async(self, name):
        """
        Asynchronously resolve DNS name to IPv4 and IPv6 addresses.

        Args:
            name (str): DNS name to resolve

        Returns:
            tuple: (ipv4_list, ipv6_list) containing resolved addresses
        """
        ipv4, ipv6 = [], []

        try:
            # Resolve A records (IPv4)
            try:
                result = await self.async_resolver.query(name, "A")
                ipv4 = sorted([r.host for r in result])
                if ipv4:
                    with self._stats_lock:
                        self.stats["dns_records_link_to_ipv4"] += 1
            except aiodns.error.DNSError:
                pass

            # Resolve AAAA records (IPv6)
            try:
                result = await self.async_resolver.query(name, "AAAA")
                ipv6 = sorted([r.host for r in result])
                if ipv6:
                    with self._stats_lock:
                        self.stats["dns_records_link_to_ipv6"] += 1
            except aiodns.error.DNSError:
                pass

        except Exception as e:
            self.logger.debug(f"Async DNS resolution failed for {name}: {e}")
            return [], []

        return ipv4, ipv6

    async def _resolve_dns_names_async(self, dns_names):
        """
        Resolve multiple DNS names asynchronously with concurrency limit.

        Args:
            dns_names (list): List of DNS names to resolve

        Returns:
            dict: Mapping of DNS name to resolution results
        """
        if not dns_names:
            return {}

        result = {}
        semaphore = asyncio.Semaphore(DEFAULT_BATCH_SIZE)

        async def resolve_with_semaphore(name):
            async with semaphore:
                ipv4, ipv6 = await self._resolve_dns_async(name)
                return name, ipv4, ipv6

        try:
            # Create tasks for all DNS names
            tasks = [resolve_with_semaphore(name) for name in dns_names]

            # Execute with timeout
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=60.0)

            # Process results
            for task_result in results:
                if isinstance(task_result, Exception):
                    self.logger.debug(f"DNS resolution task failed: {task_result}")
                    continue

                name, ipv4, ipv6 = task_result
                if ipv4 or ipv6:
                    result[name] = {
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "dual_stack": bool(ipv4 and ipv6),
                    }

            successful = sum(1 for r in results if not isinstance(r, Exception) and (r[1] or r[2]))

            with self._stats_lock:
                self.stats["async_dns_successful"] += successful
            return result

        except Exception as e:
            self.logger.warning(f"Async DNS resolution failed: {e}")
            with self._stats_lock:
                self.stats["async_dns_errors"] += 1
            return {}

    def resolve_dns_names(self, dns_names):
        """
        Resolve DNS names to IPv4 and IPv6 addresses with async tasks.

        Args:
            dns_names (list): List of DNS names to resolve

        Returns:
            dict: Mapping of DNS name to resolution results with IPv4/IPv6 addresses
        """
        if not dns_names:
            return {}

        result = {}

        try:
            # Run async DNS resolution
            loop = None
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            if loop.is_running():
                # If we're already in an async context, create a new event loop
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(self._run_async_dns, dns_names)
                    result = future.result(timeout=65.0)
            else:
                result = loop.run_until_complete(self._resolve_dns_names_async(dns_names))

            if result:
                self.logger.debug(f"Async DNS resolved {len(result)} names")
                return result
            else:
                self.logger.debug("Async DNS returned no results")

        except Exception as e:
            self.logger.warning(f"Async DNS resolution failed: {e}")
            with self._stats_lock:
                self.stats["async_dns_errors"] += 1

        return result

    def _run_async_dns(self, dns_names):
        """
        Helper method to run async DNS in a new event loop.

        Args:
            dns_names (list): List of DNS names to resolve

        Returns:
            dict: DNS resolution results
        """
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self._resolve_dns_names_async(dns_names))
        finally:
            loop.close()

    def get_dns_records_bulk(self, sys_ids, include_inactive=False):
        """
        Retrieve DNS records for multiple CIs efficiently.

        Args:
            sys_ids (list): List of CI sys_ids
            include_inactive (bool): Include inactive DNS records

        Returns:
            dict: Mapping of CI sys_id to list of DNS record dictionaries
        """
        results = self._batch_api_call(
            endpoint="cmdb_ci_dns_name",
            sys_ids=sys_ids,
            query_template="u_cmdb_ciIN{}",
            fields="u_cmdb_ci,name",
            include_inactive=include_inactive,
            limit_per_id=10,
        )

        # Group results by CI sys_id
        dns_records_map = defaultdict(list)
        for record in results:
            ci_sys_id = record["u_cmdb_ci"]["value"]
            dns_name = record.get("name", "").strip()

            if dns_name:  # Only store non-empty DNS names
                dns_records_map[ci_sys_id].append({"dns_name": dns_name})

        total_dns_records = sum(len(records) for records in dns_records_map.values())
        self.logger.debug(f"Found {total_dns_records} DNS records for {len(dns_records_map)} CIs")

        return dict(dns_records_map)

    def get_contained_children(self, parent_sys_ids, include_inactive=False):
        """
        Get containment children for multiple parent CIs.

        Args:
            parent_sys_ids (list): List of parent CI sys_ids
            include_inactive (bool): Include relationships with inactive CIs

        Returns:
            dict: Mapping of parent sys_id to list of child sys_ids
        """
        # The relationship can be active even if the related CI is inactive.
        # As a result this will return inactive CIs for some elements
        query_template = "parentIN{}^type=" + "%2C".join(RELATIONSHIP_SYS_ID)
        results = self._batch_api_call(
            endpoint="cmdb_rel_ci",
            sys_ids=parent_sys_ids,
            query_template=query_template,
            fields="parent,child",
            include_inactive=include_inactive,
            limit_per_id=100,
        )

        # Group results by parent
        children_map = defaultdict(list)
        for rel in results:
            parent_id = rel["parent"]["value"]
            child_id = rel["child"]["value"]
            children_map[parent_id].append(child_id)
            self.logger.debug(f"Parent {parent_id} contains child {child_id}")
            self.logger.debug(f"{parent_id}:{self._generate_links(parent_id)}")
            self.logger.debug(f"{child_id}:{self._generate_links(child_id)}")

        total_children = sum(len(children) for children in children_map.values())
        self.logger.debug(f"Found {total_children} child relationships for {len(children_map)} parents")

        return dict(children_map)

    def get_ci_details_bulk(self, sys_ids, include_inactive=False):
        """
        Retrieve CI details with DNS records and IP resolution.

        Args:
            sys_ids (list): List of CI sys_ids
            include_inactive (bool): Include inactive CIs

        Returns:
            dict: Mapping of sys_id to CI details with enhanced data
        """
        if not sys_ids:
            return {}

        # Get basic CI details
        results = self._batch_api_call(
            endpoint="cmdb_ci",
            sys_ids=sys_ids,
            query_template="sys_idIN{}",
            fields="sys_id,name",
            include_inactive=include_inactive,
            limit_per_id=2,
        )

        # Build details dictionary with enhanced data
        details = {}
        for ci in results:
            details[ci["sys_id"]] = {
                **ci,
                "dns_records": [],
                "ip_addresses": {},
                **self._generate_links(ci["sys_id"]),
            }

        # Get DNS records and resolve IP addresses
        if details:
            self._add_dns_info(details, include_inactive)

        # Log statistics
        missing_count = len(sys_ids) - len(details)
        if missing_count > 0:
            status = "inactive or missing" if not include_inactive else "missing"
            self.logger.warning(f"{missing_count} CIs not retrieved (may be {status})")
            if self.logger.isEnabledFor(logging.DEBUG):
                missing_ids = sorted(set(sys_ids) - set(details.keys()))
                self.logger.debug(f"Missing sys_ids: {missing_ids}")
                for _id in missing_ids:
                    self.logger.debug(f"Missing: {self._generate_links(_id)}")

        return details

    def _add_dns_info(self, details, include_inactive):
        """
        Enhance CI details with DNS records and IP address resolution.

        Args:
            details (dict): CI details dictionary to enhance
            include_inactive (bool): Include inactive DNS records
        """
        self.logger.info("Fetching DNS records for retrieved CIs")
        try:
            dns_records_map = self.get_dns_records_bulk(list(details.keys()), include_inactive)

            # Attach DNS records and resolve IP addresses
            for sys_id, dns_records in dns_records_map.items():
                if sys_id in details:
                    dns_names = sorted({record["dns_name"] for record in dns_records})
                    details[sys_id]["dns_records"] = dns_names

                    # Resolve DNS names to IP addresses
                    if dns_names:
                        details[sys_id]["ip_addresses"] = self.resolve_dns_names(dns_names)

            with self._stats_lock:
                self.stats["dns_records_retrieved"] = sum(len(records) for records in dns_records_map.values())

        except ServiceNowAPIError as e:
            self.logger.warning(f"Failed to retrieve DNS records: {e}")

    def build_tree(self, root_sys_id, max_depth=None, include_inactive=False):
        """
        Build containment tree using breadth-first traversal with cycle detection.

        This method efficiently traverses the containment hierarchy by processing
        nodes level-by-level, which allows for optimal batching of API calls.

        Args:
            root_sys_id (str): Root CI sys_id to start traversal
            max_depth (int, optional): Maximum tree depth to traverse
            include_inactive (bool): Include inactive CIs and relationships

        Returns:
            dict: Tree structure with nested children, or None if root has no relevant data
        """
        visited = set()
        to_visit = deque([(root_sys_id, 0)])
        parent_map = defaultdict(list)

        self.logger.info(f"Starting tree traversal from root: {root_sys_id}")
        if max_depth:
            self.logger.info(f"Maximum depth limit: {max_depth}")

        # Level-by-level traversal for optimal batching
        while to_visit:
            current_depth = to_visit[0][1]
            current_level = []

            # Collect all nodes at current depth
            while to_visit and to_visit[0][1] == current_depth:
                sys_id, depth = to_visit.popleft()
                if max_depth and depth >= max_depth:
                    continue
                if sys_id in visited:
                    continue
                visited.add(sys_id)
                current_level.append(sys_id)

            if not current_level:
                break

            self.logger.debug(f"Depth {current_depth}: Processing {len(current_level)} nodes")

            # Get children for all nodes at this level
            try:
                child_map = self.get_contained_children(current_level, include_inactive)
            except ServiceNowAPIError as e:
                self.logger.error(f"Failed to get children for level {current_depth}: {e}")
                continue

            # Queue children for next level
            new_nodes = 0
            for parent, children in child_map.items():
                parent_map[parent].extend(children)
                for child in children:
                    if child not in visited:
                        to_visit.append((child, current_depth + 1))
                        new_nodes += 1

            self.logger.debug(f"Queued {new_nodes} new nodes for next level")

        # Get details for all discovered nodes
        all_ids = list(visited)
        self.logger.info(f"Tree traversal complete. Total nodes: {len(all_ids)}")

        try:
            ci_details = self.get_ci_details_bulk(all_ids, include_inactive)
        except ServiceNowAPIError as e:
            self.logger.error(f"Failed to get CI details: {e}")
            ci_details = {}

        # Build tree structure recursively
        def build_node(sys_id, depth=0):
            """
            Recursively build tree node with pruning logic.

            Nodes are pruned if they have no DNS records and no children,
            reducing noise in the output tree.
            """
            ci_data = ci_details.get(
                sys_id,
                {
                    "sys_id": sys_id,
                    "name": "UNKNOWN",
                    "dns_records": [],
                    "ip_addresses": {},
                    **self._generate_links(sys_id),
                },
            )

            # Build children recursively
            children = []
            for child_id in parent_map.get(sys_id, []):
                child_node = build_node(child_id, depth + 1)
                if child_node is not None:
                    children.append(child_node)

            # Check if node has meaningful data
            dns_records = ci_data.get("dns_records", [])
            ip_addresses = ci_data.get("ip_addresses", {})
            has_dns_data = bool(dns_records)

            # Prune nodes without DNS data and no children
            if not has_dns_data and not children:
                return None

            # Build node structure
            node = {
                "name": ci_data.get("name", "UNKNOWN"),
                "sys_id": sys_id,
                "api_link": ci_data.get("api_link"),
                "ui_link": ci_data.get("ui_link"),
                "depth": depth,
            }

            # Add DNS data if present
            if has_dns_data:
                node["dns_records"] = dns_records
                if ip_addresses:
                    node["ip_addresses"] = ip_addresses

            # Add children if present
            if children:
                node["children"] = children

            return node

        tree = build_node(root_sys_id)
        self.logger.info("Tree construction complete")
        return tree

    def get_ci_by_sysid(self, sys_id, table="cmdb_ci"):
        """
        Retrieve single CI by sys_id for debugging purposes.

        Args:
            sys_id (str): CI sys_id
            table (str): ServiceNow table name

        Returns:
            dict: CI record or empty dict on failure
        """
        try:
            params = {"sysparm_query": f"sys_id={sys_id}", "sysparm_limit": "1"}
            result = self._make_api_request(f"{self.base_url}/{table}", params)

            if result:
                ci_data = result[0]
                self.logger.debug(f"CI info for {sys_id}:\n{pprint.pformat(ci_data)}")
                return ci_data

        except ServiceNowAPIError as e:
            self.logger.error(f"Failed to get CI {sys_id}: {e}")

        return {}

    def validate_connection(self):
        """
        Test connection to ServiceNow instance.

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            params = {"sysparm_limit": "1"}
            self._make_api_request(f"{self.base_url}/cmdb_ci", params)
            return True
        except ServiceNowAPIError:
            return False

    def get_relationships(self, sys_id):
        """
        Get all relationships for a CI (for debugging).

        Args:
            sys_id (str): CI sys_id

        Returns:
            list: List of relationship records
        """
        try:
            params = {
                "sysparm_query": f"parent={sys_id}^ORchild={sys_id}",
                "sysparm_fields": "sys_id,parent,child,type",
                "sysparm_limit": "2000",
                "sysparm_display_value": "false",
            }

            result = self._make_api_request(f"{self.base_url}/cmdb_rel_ci", params)
            self.logger.debug(f"Relationships for {sys_id}:\n{pprint.pformat(result)}")
            return result

        except ServiceNowAPIError as e:
            self.logger.error(f"Failed to get relationships for {sys_id}: {e}")
            return []


def setup_logging(log_level, log_file=None):
    """
    Configure logging with appropriate format and output destination.

    Args:
        log_level (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file (str, optional): Log file path, uses stdout if not specified
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(numeric_level)

    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Setup appropriate handler
    handler = logging.FileHandler(log_file) if log_file else logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def main():
    """Main entry point with argument parsing and execution flow."""
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Build ServiceNow CMDB containment trees with DNS records and IP resolution.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --sys-id abc123 --log-level DEBUG
  %(prog)s --sys-id abc123 --batch-size 25 --max-depth 3 --output tree.json
  %(prog)s --sys-id abc123 --include-inactive --log-file app.log

Dependencies:
  Required: requests, python-dotenv, dnspython
  Optional: aiodns (for async DNS resolution - will fallback to sync if not available)
        """,
    )

    # Required arguments
    parser.add_argument("--sys-id", required=True, help="Root CI sys-id to start tree traversal")

    # Connection arguments
    parser.add_argument(
        "--instance", default=os.getenv("SNOW_INSTANCE"), help="ServiceNow instance domain [env: SNOW_INSTANCE]"
    )
    parser.add_argument(
        "--username", default=os.getenv("SNOW_USERNAME"), help="ServiceNow API username [env: SNOW_USERNAME]"
    )
    parser.add_argument(
        "--password", default=os.getenv("SNOW_PASSWORD"), help="ServiceNow API password [env: SNOW_PASSWORD]"
    )

    # Optional arguments
    parser.add_argument(
        "--output", type=argparse.FileType("w"), default=sys.stdout, help="Output file for JSON tree (default: stdout)"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set logging level (default: INFO)",
    )
    parser.add_argument("--log-file", help="Log file path (default: stdout)")
    parser.add_argument(
        "--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help=f"API batch size (default: {DEFAULT_BATCH_SIZE})"
    )
    parser.add_argument("--max-depth", type=int, help="Maximum tree depth to traverse")
    parser.add_argument("--include-inactive", action="store_true", help="Include inactive CIs and DNS records")

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level, args.log_file)
    logger = logging.getLogger(__name__)

    # Validate required credentials
    missing = []
    for var, name in [(args.instance, "instance"), (args.username, "username"), (args.password, "password")]:
        if not var:
            missing.append(name)

    if missing:
        parser.error(f"Missing required arguments or environment variables: {', '.join(missing)}")

    # Execute main workflow
    try:
        explorer = ServiceNowCMDBExplorer(args.instance, args.username, args.password, batch_size=args.batch_size)

        # Validate connection
        if not explorer.validate_connection():
            logger.error("Could not connect to ServiceNow instance")
            sys.exit(1)

        logger.info("Connection validated successfully")

        # Debug information if requested
        if logger.isEnabledFor(logging.DEBUG):
            explorer.get_ci_by_sysid(args.sys_id)
            explorer.get_relationships(args.sys_id)

        # Build and output tree
        tree = explorer.build_tree(args.sys_id, max_depth=args.max_depth, include_inactive=args.include_inactive)

        json.dump(tree, args.output, indent=2, ensure_ascii=False)
        args.output.write("\n")

        logger.info("Tree output complete")
        explorer._print_stats()

    except ServiceNowAPIError as e:
        logger.error(f"ServiceNow API error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.error("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
