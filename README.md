# NESSUS_Scan

This is a project that uses the Tenable Nessus API to gather scan data to be used with Tableau to create a Netword Scan Dashboard.

The scripts work together to do the following:
1. Login to the API and create a session token
2. Using the new session token, a request is made of a specific scan id.
3. The resulting JSON response is then parsed out into several data groups.
4. Each group is then cleaned up and sent to specific Oracle tables.

Once all the tables have been updated, a table relationship is built in Tableau and a dashboard is used to display
the resulting metrics to the Network Management team.
