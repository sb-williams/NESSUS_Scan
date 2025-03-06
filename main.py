import os
import sys
import pandas as pd 
import json
from dotenv import load_dotenv
import oracledb
import requests
import write_response
import data_tables

# these 2 lines are just here to improve the display of results to the console.
# they can be commented out if not needed.
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)

# DO NOT comment out this line
load_dotenv()

# Set up the variables to be used to login and connect to Nessus and generate an access token
base_url = "https://abwpnessus01.corp.bpu.local:8834/"
access_key = os.environ.get("ACCESS_KEY")
secret_key = os.environ.get("SECRET_KEY")
username = os.environ.get("USER_NAME")
password = os.environ.get("USER_PASSWORD")

# Create a token
auth_url = f"{base_url}/session"
auth_data = {"username": username, "password": password}
token_response = requests.post(auth_url, json=auth_data, verify=False)
token = token_response.json()["token"]
print('Session token created')

# Once we have our token, we can connect and get data back from the API
# We are using Scan ID 1811 to get all DMZ data. We can select
# a different scan id to collect different data.
scanner_url = f"{base_url}/scans/{1811}?token={token}"
print('Data request sent to API')
scan_response = requests.get(scanner_url, verify=False)

# Load the data into a dataframe
scan_content =json.loads(scan_response.content)
scan_temp = pd.json_normalize(scan_content['info'])
scan_hosts = pd.json_normalize(scan_content['hosts'])
scan_prioritization = pd.json_normalize(scan_content['prioritization']['plugins'])
print('Requested data returned from API')

# This line can be used to create a json text file that can be
# used in an online parser to review the result response and to assist in
# mapping out additional data needs. Comment/uncomment as needed.
# write_response.write_json_tofile(host_response)

# The following code is used to grab different pieces of data from the result set. Each
# section will go and collect different sections of data and then save that data to a corresponding
# Oracle table. These tables will then be used to build out the Nessus Dashboard.

# INFO DATA
df_info = pd.DataFrame(scan_temp)
df_info_selected = df_info[["name", "scan_type", "policy", "hostcount"]]
data_tables.load_info_data(df_info_selected)


# HOSTS DATA
df_hosts = pd.DataFrame(scan_hosts)
df_hosts = df_hosts.drop('severitycount.item', axis=1)
data_tables.load_host_data(df_hosts)

# HOST PLUGIN DATA
# There are several embedded arrays that make up the plug-in and solution data.
# This loop is very complex with the goal of collecting all the plugin data as well
# as assigning the affected host info for each plug-in

# Gather the base plugin data based on severity prioritization
df_prioritization_plugins = pd.DataFrame(scan_prioritization)

# Get all our plugin data (minus host info)
df_plugin_final = df_prioritization_plugins[["severity", "pluginname", "pluginid"
,"pluginattributes.synopsis", "pluginattributes.description", "pluginattributes.risk_information.risk_factor",
"pluginattributes.product_coverage", "pluginattributes.plugin_information.plugin_version", 
"pluginattributes.plugin_information.plugin_family", "pluginattributes.solution", "pluginattributes.age_of_vuln"]]

# These next 5 lines look messy, but these are the steps required to isolate
# each host per plugin.
df_plugin_hosts = pd.DataFrame(df_prioritization_plugins['hosts'])
df_plugin_hosts_temp = pd.DataFrame(df_plugin_hosts['hosts'])
df_plugin_hosts_details = pd.DataFrame(df_plugin_hosts_temp['hosts'])
df_plugin_hosts_alpha = pd.DataFrame(df_plugin_hosts_details['hosts'])

# This is the final host isolation output
df_plugin_hosts_beta = pd.json_normalize(df_plugin_hosts_alpha['hosts'])

# Due to the level of the array, we can grab the host info,
# then concatenate it to our primary data result.
host_list_id = df_plugin_hosts_beta[0].apply(lambda row: row['id'])
host_list_name = df_plugin_hosts_beta[0].apply(lambda row: row['hostname'])


# Since the host data has no column name, we need to add them one at a time,
# so we avoid Pandas creating duplicate column names.

# Add and rename Host ID column first
df_plugin_final = pd.concat([df_plugin_final, host_list_id], axis=1)
df_plugin_final.rename(columns={0: 'Host_ID'}, inplace=True)

# Finally, add and rename the Host Name column
df_plugin_final = pd.concat([df_plugin_final, host_list_name], axis=1)
df_plugin_final.rename(columns={0: 'Host_Name'}, inplace=True)

# Now that we have all the data, we need to clean up the data a bit.
# Some of the column headers are long due to the nature of how we had to
# get the data, so lets shorten some of them a bit to fit our table
df_plugin_final.rename(columns={
    'pluginname': 'plugin_name',
    'pluginid': 'plugin_id',
    'pluginattributes.synopsis': 'synopsis',
    'pluginattributes.description': 'plugin_description',
    'pluginattributes.risk_information.risk_factor': 'risk_factor',
    'pluginattributes.product_coverage': 'product_coverage',
    'pluginattributes.plugin_information.plugin_version' : 'plugin_version',
    'pluginattributes.plugin_information.plugin_family': 'plugin_family',
    'pluginattributes.solution': 'solution',
    'pluginattributes.age_of_vuln': 'age_of_vuln'
}, inplace=True)

# Now that we have it all cleaned up and organized, we can update our oracle table
data_tables.load_plugin_data(df_plugin_final)

# VULNERABILITIES DATA
df_vulnerabilities = pd.DataFrame(scan_content['vulnerabilities'])
df_vulnerabilities = df_vulnerabilities.drop('epss_score', axis=1)
data_tables.load_vuln_data(df_vulnerabilities)

print('API Data Update completed!')
sys.exit(0)