# snow-cmdb-tree

Query the FNAL ServiceNow CMDB (Configuration Management Database) to determine which hosts are contained within various cluster relationships. This tool is designed to automate discovery of host memberships in clusters at Fermilab, using ServiceNow’s API.

---

## Features

- **Cluster Membership Discovery**: Given the ServiceNow sys_id of a cluster or host, recursively queries the FNAL ServiceNow CMDB to enumerate all contained hosts.
- **Automation Ready**: Supports environment variable configuration for integration in scripts and CI/CD pipelines.

---

## Getting Started

### Installation

Clone this repository and install dependencies (if needed).

### Usage

You'll need the `sysid` of your top-level cluster or host from ServiceNow.

```shell
./snow-cmdb-tree --sys-id=<sysid>
```

#### Environment Variables

Set the following environment variables for authentication and API configuration:

- `SNOW_INSTANCE=fermi.servicenowservices.com`
- `SNOW_USERNAME=your_automation_user`
- `SNOW_PASSWORD=password_for_automation_user`

You may also supply these via a `.env` file or your preferred secret management system.

---

## API Details

This script queries the FNAL ServiceNow CMDB using ServiceNow’s REST API. At minimum, you need:

- **sys_id** (string): The ServiceNow unique identifier for the cluster or host to query.
- **Authentication**: Username/Password for an account with read access to the CMDB.

**API Endpoints Used:**
- Typically: `https://<SNOW_INSTANCE>/api/now/table/cmdb_ci`
- Filtering and recursion are handled via the script.

**Data Returned:**
- List of hosts contained within the given cluster, including nested clusters.

---

## Output

The script outputs a tree structure of hosts and clusters in json.

---

## Troubleshooting

- **Authentication Errors**: Double-check `SNOW_USERNAME`, `SNOW_PASSWORD`, and `SNOW_INSTANCE`. Ensure your account has CMDB read permissions.
- **No Results Returned**: Verify the `sysid` is correct and exists in ServiceNow. Use ServiceNow’s web interface to confirm.
- **Connection Issues**: Ensure you have network access to `fermi.servicenowservices.com` and ServiceNow’s API is up.
- **Unexpected Output**: Check for ServiceNow schema changes. The script expects standard relationships; customizations may require code updates.

