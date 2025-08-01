#!/usr/bin/env python3

import argparse
import json
import logging
import os
import pprint
import sys
import time
from collections import defaultdict, deque
from urllib.parse import urlencode

import dns.exception
import dns.resolver
import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# Configuration constants
CONTAINS_REL_TYPE_SYS_ID = "55c95bf6c0a8010e0118ec7056ebc54d"
DEFAULT_BATCH_SIZE = 50
MAX_RETRIES = 3
RETRY_DELAY = 2
REQUEST_TIMEOUT = 30
MAX_URL_LENGTH = 8000


class ServiceNowAPIError(Exception):
    """Custom exception for ServiceNow API errors"""

    pass


class ServiceNowCMDBExplorer:
    def __init__(self, instance, username, password, batch_size=DEFAULT_BATCH_SIZE):
        self.logger = logging.getLogger(__name__)
        self.instance = instance
        self.batch_size = batch_size
        self.base_url = f"https://{instance}/api/now/table"

        # Setup a DNS resolver
        self.dns_resolver = dns.resolver.Resolver()

        # Session setup with auth and headers
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

    def _print_stats(self):
        """Print API usage statistics"""
        self.logger.info("=== API Usage Statistics ===")
        for key, value in self.stats.items():
            self.logger.info(f"{key.replace('_', ' ').title()}: {value}")
        self.logger.info("=============================")

    def _generate_links(self, sys_id, table="cmdb_ci"):
        """Generate both API and UI links for a CI"""
        return {
            "api_link": f"https://{self.instance}/api/now/table/{table}/{sys_id}",
            "ui_link": f"https://{self.instance}/nav_to.do?uri={table}.do?sys_id={sys_id}",
        }

    def _estimate_batch_size(self, sys_ids):
        """Dynamically estimate optimal batch size based on URL length"""
        if not sys_ids:
            return self.batch_size

        avg_id_length = sum(len(sid) for sid in sys_ids) / len(sys_ids)
        base_overhead = 200  # Conservative estimate for base URL + params
        max_ids = (MAX_URL_LENGTH - base_overhead) // (avg_id_length + 1)

        return min(self.batch_size, max(1, int(max_ids * 0.8)))

    def _make_api_request(self, url, params, max_retries=MAX_RETRIES):
        """Make HTTP request with retry logic and comprehensive error handling"""
        for attempt in range(max_retries + 1):
            try:
                self.stats["api_calls"] += 1

                # URL length warning
                full_url = f"{url}?{urlencode(params)}"
                if len(full_url) > MAX_URL_LENGTH:
                    self.logger.warning(f"URL length ({len(full_url)}) may exceed limits")

                response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", RETRY_DELAY * (attempt + 1)))
                    self.logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                result = response.json()

                if "result" not in result:
                    raise ServiceNowAPIError(f"Unexpected response format: missing 'result' key")

                self.stats["total_records"] += len(result["result"])
                return result["result"]

            except requests.exceptions.Timeout:
                if attempt < max_retries:
                    self.stats["retries"] += 1
                    delay = RETRY_DELAY * (attempt + 1)
                    self.logger.warning(f"Request timeout. Retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                raise ServiceNowAPIError(f"Request timeout after {max_retries + 1} attempts")

            except requests.exceptions.RequestException as e:
                if attempt < max_retries:
                    self.stats["retries"] += 1
                    delay = RETRY_DELAY * (attempt + 1)
                    self.logger.warning(f"Request failed: {e}. Retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                self.stats["failed_requests"] += 1
                raise ServiceNowAPIError(f"Request failed after {max_retries + 1} attempts: {e}")

        raise ServiceNowAPIError("Maximum retries exceeded")

    def _build_query_with_filters(self, base_query, include_inactive=False):
        """Build query string with optional inactive filtering"""
        query_parts = [base_query]

        if not include_inactive:
            query_parts.extend(["parent.u_active=true", "child.u_active=true"])

        return "^".join(query_parts)

    def resolve_dns_names(self, dns_names):
        """Resolve a list of DNS names to IPv4 and IPv6 addresses"""
        result = {}

        self.stats["dns_records_checked_ipv4"] = 0
        self.stats["dns_records_checked_ipv6"] = 0
        for name in dns_names:
            ipv4, ipv6 = [], []

            try:
                self.stats["dns_records_checked_ipv4"] += 1
                answers = self.dns_resolver.resolve(name, "A")
                ipv4 = sorted([r.to_text() for r in answers]) if answers.rrset else []
            except dns.exception.DNSException:
                pass

            try:
                self.stats["dns_records_checked_ipv6"] += 1
                answers = self.dns_resolver.resolve(name, "AAAA")
                ipv6 = sorted([r.to_text() for r in answers]) if answers.rrset else []
            except dns.exception.DNSException:
                pass

            if ipv4 or ipv6:
                result[name] = {
                    "ipv4": ipv4,
                    "ipv6": ipv6,
                    "dual_stack": bool(ipv4 and ipv6),
                }

        return result

    def get_dns_records_bulk(self, sys_ids, include_inactive=False):
        """Get DNS records for multiple CI sys_ids with intelligent batching"""
        if not sys_ids:
            return {}

        dns_records_map = defaultdict(list)
        batch_size = self._estimate_batch_size(sys_ids)

        self.logger.debug(f"Fetching DNS records for {len(sys_ids)} CIs with batch size {batch_size}")

        # Process in batches
        for i in range(0, len(sys_ids), batch_size):
            batch = sys_ids[i : i + batch_size]
            self.logger.debug(f"Processing DNS batch {i//batch_size + 1}: {len(batch)} items")

            try:
                # Build query for batch of sys_ids - using IN operator for batch
                # For reference fields, we need to use the field name directly with IN
                query = f"u_cmdb_ciIN{','.join(batch)}"

                if not include_inactive:
                    query += "^u_active=true"

                params = {
                    "sysparm_query": query,
                    "sysparm_fields": "u_cmdb_ci,name",
                    "sysparm_limit": str(len(batch) * 10),  # Allow multiple DNS records per CI
                    "sysparm_display_value": "false",
                }

                dns_records = self._make_api_request(f"{self.base_url}/cmdb_ci_dns_name", params)
                self.logger.debug(f"Retrieved {len(dns_records)} DNS records for batch")

                # Group results by CI sys_id
                for record in dns_records:
                    ci_sys_id = record["u_cmdb_ci"]["value"]
                    dns_name = record.get("name", "")

                    if dns_name:  # Only add non-empty DNS names
                        dns_records_map[ci_sys_id].append(
                            {"dns_name": dns_name, "active": record.get("u_active", "false") == "true"}
                        )

            except ServiceNowAPIError as e:
                self.logger.warning(f"DNS batch query failed: {e}. Falling back to individual queries")

                # Fallback to individual queries
                for sys_id in batch:
                    try:
                        query = f"u_cmdb_ci={sys_id}"

                        if not include_inactive:
                            query += "^u_active=true"

                        params = {
                            "sysparm_query": query,
                            "sysparm_fields": "u_cmdb_ci,name,u_active",
                            "sysparm_limit": "50",  # Reasonable limit per CI
                            "sysparm_display_value": "false",
                        }

                        dns_records = self._make_api_request(f"{self.base_url}/cmdb_ci_dns_name", params, max_retries=1)

                        for record in dns_records:
                            dns_name = record.get("name", "")

                            if dns_name:  # Only add non-empty DNS names
                                dns_records_map[sys_id].append(
                                    {"dns_name": dns_name, "active": record.get("u_active", "false") == "true"}
                                )

                    except ServiceNowAPIError as e:
                        self.logger.debug(f"Individual DNS query failed for {sys_id}: {e}")
                        continue

        total_dns_records = sum(len(records) for records in dns_records_map.values())
        self.logger.debug(f"Found {total_dns_records} total DNS records for {len(dns_records_map)} CIs")

        return dict(dns_records_map)

    def get_contained_children(self, parent_sys_ids, include_inactive=False):
        """Get children for multiple parent sys_ids with intelligent batching"""
        if not parent_sys_ids:
            return {}

        children_map = defaultdict(list)
        batch_size = self._estimate_batch_size(parent_sys_ids)

        self.logger.debug(f"Processing {len(parent_sys_ids)} parent sys_ids with batch size {batch_size}")

        # Process in batches
        for i in range(0, len(parent_sys_ids), batch_size):
            batch = parent_sys_ids[i : i + batch_size]
            self.logger.debug(f"Processing batch {i//batch_size + 1}: {len(batch)} items")

            try:
                # Try batched query first
                parent_query = f"parentIN{','.join(batch)}^type={CONTAINS_REL_TYPE_SYS_ID}"
                full_query = self._build_query_with_filters(parent_query, include_inactive)

                params = {
                    "sysparm_query": full_query,
                    "sysparm_fields": "parent,child",
                    "sysparm_limit": "10000",
                    "sysparm_display_value": "false",
                }

                relationships = self._make_api_request(f"{self.base_url}/cmdb_rel_ci", params)
                self.logger.debug(f"Batched query returned {len(relationships)} relationships")

                # Group results by parent
                for rel in relationships:
                    parent_id = rel["parent"]["value"]
                    child_id = rel["child"]["value"]
                    children_map[parent_id].append(child_id)

            except ServiceNowAPIError as e:
                self.logger.warning(f"Batched query failed: {e}. Falling back to individual queries")

                # Fallback to individual queries
                for sys_id in batch:
                    try:
                        query = f"parent={sys_id}^type={CONTAINS_REL_TYPE_SYS_ID}"
                        full_query = self._build_query_with_filters(query, include_inactive)

                        params = {
                            "sysparm_query": full_query,
                            "sysparm_fields": "parent,child",
                            "sysparm_limit": "1000",
                            "sysparm_display_value": "false",
                        }

                        relationships = self._make_api_request(f"{self.base_url}/cmdb_rel_ci", params, max_retries=1)

                        for rel in relationships:
                            parent_id = rel["parent"]["value"]
                            child_id = rel["child"]["value"]
                            children_map[parent_id].append(child_id)

                    except ServiceNowAPIError as e:
                        self.logger.debug(f"Individual query failed for {sys_id}: {e}")
                        continue

        total_children = sum(len(children) for children in children_map.values())
        self.logger.debug(f"Found {total_children} total child relationships for {len(children_map)} parents")

        return dict(children_map)

    def get_ci_details_bulk(self, sys_ids, include_inactive=False):
        """Get CI details in optimized batches with DNS records"""
        if not sys_ids:
            return {}

        details = {}
        chunk_size = self._estimate_batch_size(sys_ids)

        self.logger.debug(f"Fetching details for {len(sys_ids)} CIs in chunks of {chunk_size}")

        # Process in chunks
        for i in range(0, len(sys_ids), chunk_size):
            chunk = sys_ids[i : i + chunk_size]

            try:
                query = f"sys_idIN{','.join(chunk)}"

                if not include_inactive:
                    query += "^u_active=true"

                params = {
                    "sysparm_query": query,
                    "sysparm_fields": "sys_id,name,sys_class_name",
                    "sysparm_limit": str(len(chunk) * 2),  # Safety margin
                    "sysparm_display_value": "false",
                }

                cis = self._make_api_request(f"{self.base_url}/cmdb_ci", params)
                self.logger.debug(f"Retrieved {len(cis)} CI details for chunk")

                # Store results with enhanced data (without DNS records yet)
                for ci in cis:
                    details[ci["sys_id"]] = {
                        **ci,
                        "dns_records": [],  # Will be populated below
                        **self._generate_links(ci["sys_id"]),
                    }

            except ServiceNowAPIError as e:
                self.logger.warning(f"Failed to get details for chunk: {e}")
                continue

        # Get DNS records for all CIs that were successfully retrieved
        if details:
            self.logger.info("Fetching DNS records for retrieved CIs")
            try:
                dns_records_map = self.get_dns_records_bulk(list(details.keys()), include_inactive)

                # Attach DNS records to CI details
                for sys_id, dns_records in dns_records_map.items():
                    if sys_id in details:
                        details[sys_id]["dns_records"] = sorted({record['dns_name'] for record in dns_records})

                self.stats["dns_records_retrieved"] += sum(len(records) for records in dns_records_map.values())


            except ServiceNowAPIError as e:
                self.logger.warning(f"Failed to retrieve DNS records: {e}")
                # Continue without DNS records - CIs will have empty dns_records lists

            self.logger.info(f"Resolving DNS names to IP addresses")
            try:
                for sysid in details:
                    if details[sysid]['dns_records']:
                        details[sysid]['ip_addresses'] = self.resolve_dns_names(details[sysid]['dns_records'])
            except Exception as e:
                self.logger.warning(f"Failed to resolve DNS records: {e}")
                # Continue without resolving DNS records - CIs will have empty ip_addresses

        # Log missing CIs
        missing_count = len(sys_ids) - len(details)
        if missing_count > 0:
            status = "inactive or missing" if not include_inactive else "missing"
            self.logger.warning(f"{missing_count} CIs not retrieved (may be {status})")

        return details

    def build_tree(self, root_sys_id, max_depth=None, include_inactive=False):
        """Build containment tree with optimized traversal and cycle detection"""
        visited = set()
        to_visit = deque([(root_sys_id, 0)])
        parent_map = defaultdict(list)

        self.logger.info(f"Starting tree traversal from root: {root_sys_id}")
        if max_depth:
            self.logger.info(f"Maximum depth limit: {max_depth}")

        # Level-by-level traversal for optimal batching
        while to_visit:
            current_level = []
            current_depth = None

            # Collect all nodes at current level
            while to_visit:
                sys_id, depth = to_visit.popleft()

                if max_depth and depth >= max_depth:
                    continue

                if sys_id not in visited:
                    current_level.append(sys_id)
                    visited.add(sys_id)
                    current_depth = depth
                else:
                    # Cycle detection
                    continue

            if not current_level:
                break

            self.logger.debug(f"Depth {current_depth}: Processing {len(current_level)} nodes")

            # Get children for entire level in batch
            try:
                child_map = self.get_contained_children(current_level, include_inactive)
            except ServiceNowAPIError as e:
                self.logger.error(f"Failed to get children for level: {e}")
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
            ci_data = ci_details.get(
                sys_id,
                {
                    "sys_id": sys_id,
                    "name": "UNKNOWN",
                    "sys_class_name": "unknown",
                    "dns_records": [],
                    **self._generate_links(sys_id),
                },
            )

            # Recursively build and filter children
            children = []
            for child_id in parent_map.get(sys_id, []):
                child_node = build_node(child_id, depth + 1)
                if child_node is not None:
                    children.append(child_node)

            # Collect dns_records only if non-empty
            dns_records = ci_data.get("dns_records", [])
            has_dns_records = bool(dns_records)

            # Prune node if it has no children and no dns_records
            if not has_dns_records and not children:
                return None

            node = {
                "name": ci_data.get("name", "UNKNOWN"),
                "sys_id": sys_id,
                "sys_class_name": ci_data.get("sys_class_name", "unknown"),
                "api_link": ci_data.get("api_link"),
                "ui_link": ci_data.get("ui_link"),
                "depth": depth,
            }

            if has_dns_records:
                node["dns_records"] = dns_records

                ip_info = ci_data.get("ip_addresses")
                if ip_info:
                    node["ip_addresses"] = ip_info

            if children:
                node["children"] = children

            return node

        tree = build_node(root_sys_id)

        self.logger.info("Tree construction complete")

        return tree

    def get_ci_by_sysid(self, sys_id, table="cmdb_ci"):
        """Get single CI by sys_id"""
        result = {}
        try:
            params = {"sysparm_query": f"sys_id={sys_id}", "sysparm_limit": "1"}

            result = self._make_api_request(f"{self.base_url}/{table}", params)
            if result:
                result = result[0]

        except ServiceNowAPIError as e:
            self.logger.error(f"Failed to get CI {sys_id}: {e}")

        self.logger.debug(f"CI info for {sys_id}")
        self.logger.debug("=" * 40)
        self.logger.debug(f"\n{pprint.pformat(result)}")
        return result

    def validate_connection(self):
        """Test connection to ServiceNow instance"""
        try:
            params = {"sysparm_limit": "1"}
            self._make_api_request(f"{self.base_url}/cmdb_ci", params)
            return True
        except ServiceNowAPIError:
            return False

    def get_relationships(self, sys_id):
        """Get all relationships for a CI with error handling"""
        try:
            url = f"{self.base_url}/cmdb_rel_ci"
            params = {
                "sysparm_query": f"parent={sys_id}^ORchild={sys_id}",
                "sysparm_fields": "sys_id,parent,child,type",
                "sysparm_limit": "2000",
                "sysparm_display_value": "false",
            }

            result = self._make_api_request(url, params)
            self.logger.debug(f"Relationship info for {sys_id}")
            self.logger.debug("=" * 40)
            self.logger.debug(f"\n{pprint.pformat(result)}")

            return result

        except ServiceNowAPIError as e:
            self.logger.error(f"Failed to get relationships for {sys_id}: {e}")
            return []


def setup_logging(log_level, log_file=None):
    """Setup logging configuration"""
    # Convert string log level to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    # Create formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(numeric_level)

    # Remove any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Setup handler (file or stdout)
    if log_file:
        handler = logging.FileHandler(log_file)
    else:
        handler = logging.StreamHandler(sys.stdout)

    handler.setLevel(numeric_level)
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def main():
    # Load environment variables
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Query ServiceNow CMDB containment tree with optimized performance and DNS records.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --sys-id abc123 --log-level DEBUG
  %(prog)s --sys-id abc123 --batch-size 25 --max-depth 3 --output tree.json --log-file app.log
  %(prog)s --sys-id abc123 --include-inactive --log-level INFO
        """,
    )

    # Required arguments
    parser.add_argument("--sys-id", required=True, help="Root sys-id to start from")

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
        "--output", type=argparse.FileType("w"), default=sys.stdout, help="Output file (default: stdout)"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "debug", "info", "warning", "error", "critical"],
        default="INFO",
        help="Set the logging level (default: INFO)",
    )
    parser.add_argument("--log-file", help="Log file path (default: stdout)")
    parser.add_argument(
        "--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help=f"API batch size (default: {DEFAULT_BATCH_SIZE})"
    )
    parser.add_argument("--max-depth", type=int, help="Maximum tree depth")
    parser.add_argument("--include-inactive", action="store_true", help="Include inactive CIs and DNS records")

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level, args.log_file)
    logger = logging.getLogger(__name__)

    # Validate required credentials
    missing = [
        name
        for var, name in [(args.instance, "instance"), (args.username, "username"), (args.password, "password")]
        if not var
    ]

    if missing:
        parser.error(f"Missing required arguments or env vars: {', '.join(missing)}")

    # Initialize and validate connection
    try:
        explorer = ServiceNowCMDBExplorer(args.instance, args.username, args.password, batch_size=args.batch_size)

        if not explorer.validate_connection():
            logger.error("Could not connect to ServiceNow instance")
            sys.exit(1)

        logger.info("Connection validated successfully")
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
