# snow-cmdb-tree

Query the FNAL ServiceNow CMDB to find all computers inside a miscomp cluster


## Getting started

You'll need the `sysid` of your top level item. Then you can just run

```shell
./snow-cmdb-tree --sys-id=<sysid>
```

To generate automation you can set the following environment variables:
* SNOW_INSTANCE=fermi.servicenowservices.com
* SNOW_USERNAME=your_automation_user
* SNOW_PASSWORD=password_for_automation_user
