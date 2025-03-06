import pandas as pd
import os
import oracledb
from dotenv import load_dotenv

# This script will handle all table data updates for each API endpoint that is used.
# The corresponding table will be connected to, data updated, data committed, and then
# the connection closed.


#INFO
def load_info_data(df):
    load_dotenv()
    # Connect to a database using the env variable
    conn_test = oracledb.connect(
        user=os.environ.get("DATA_KEY"),
        password=os.environ.get("DATA_SECRET"),
        host=os.environ.get("DATA_HOST"),
        port=os.environ.get("DATA_PORT"),
        service_name=os.environ.get("SERVICE_NAME"),
    )

    cursor_test = conn_test.cursor()
    
    cursor_test.execute(
        "TRUNCATE TABLE BPU_TAB_NESSUS_MAIN"
    )
    
    rows = [tuple(x) for x in df.values]
    cursor_test.executemany(
        "INSERT INTO BPU_TAB_NESSUS_MAIN VALUES (:1,:2,:3,:4)",
        rows,
    )
    
    conn_test.commit()

    print("Main table updated")

    # Close the connection and cursor to the table and database for security reasons.
    cursor_test.close()
    conn_test.close()
    return

#HOSTS
def load_host_data(df):
    load_dotenv()
    # Connect to a database using the env variable
    conn_test = oracledb.connect(
        user=os.environ.get("DATA_KEY"),
        password=os.environ.get("DATA_SECRET"),
        host=os.environ.get("DATA_HOST"),
        port=os.environ.get("DATA_PORT"),
        service_name=os.environ.get("SERVICE_NAME"),
    )

    cursor_test = conn_test.cursor()
    
    cursor_test.execute(
        "TRUNCATE TABLE BPU_TAB_NESSUS_HOSTS_DETAIL"
    )

    rows = [tuple(x) for x in df.values]
    cursor_test.executemany(
        "INSERT INTO BPU_TAB_NESSUS_HOSTS_DETAIL VALUES (:1,:2,:3,:4,:5,:6,:7,:8,:9,:10,:11,:12,:13,:14,:15,:16,:17,:18,:19,:20)",
        rows,
    )
    
    conn_test.commit()

    print("Hosts table updated")

    # Close the connection and cursor to the table and database for security reasons.
    cursor_test.close()
    conn_test.close()
    return

#HOST PLUGIN DATA
def load_plugin_data(df):
    load_dotenv()

    # Connect to a database using the env variable
    conn_test = oracledb.connect(
        user=os.environ.get("DATA_KEY"),
        password=os.environ.get("DATA_SECRET"),
        host=os.environ.get("DATA_HOST"),
        port=os.environ.get("DATA_PORT"),
        service_name=os.environ.get("SERVICE_NAME"),
    )

    cursor_test = conn_test.cursor()
    
    cursor_test.execute(
        "TRUNCATE TABLE BPU_TAB_NESSUS_PLUGINS"
    )

    rows = [tuple(x) for x in df.values]
    cursor_test.executemany(
        "INSERT INTO BPU_TAB_NESSUS_PLUGINS VALUES (:1,:2,:3,:4,:5,:6,:7,:8,:9,:10,:11,:12,:13)",
        rows,
    )
    
    conn_test.commit()

    print("Plugins table updated")

    # # Close the connection and cursor to the table and database for security reasons.
    cursor_test.close()
    conn_test.close()
    return

#VULNERABILITY DATA
def load_vuln_data(df):
    load_dotenv()
    # Connect to a database using the env variable
    conn_test = oracledb.connect(
        user=os.environ.get("DATA_KEY"),
        password=os.environ.get("DATA_SECRET"),
        host=os.environ.get("DATA_HOST"),
        port=os.environ.get("DATA_PORT"),
        service_name=os.environ.get("SERVICE_NAME"),
    )

    cursor_test = conn_test.cursor()
    
    cursor_test.execute(
        "TRUNCATE TABLE BPU_TAB_NESSUS_VULNERABILITIES"
    )

    rows = [tuple(x) for x in df.values]
    cursor_test.executemany(
        "INSERT INTO BPU_TAB_NESSUS_VULNERABILITIES VALUES (:1,:2,:3,:4,:5,:6,:7,:8,:9,:10,:11,:12)",
        rows,
    )
    
    conn_test.commit()

    print("Vulnerabilities table updated")

    # Close the connection and cursor to the table and database for security reasons.
    cursor_test.close()
    conn_test.close()
    return

