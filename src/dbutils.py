import sqlite3 as sql
from models import Device
from config import DEBUG


def get_connection(table):
    with sql.connect("OSFP_db.db") as conn:
        cur = conn.cursor()
        cur.execute("" \
                f"CREATE TABLE IF NOT EXISTS [{table}] (" \
                "mac_address TEXT PRIMARY KEY, " \
                "is_randomized_mac BOOLEAN DEFAULT FALSE, " \
                "hostname TEXT NULLABLE, " \
                "net_config TEXT NULLABLE, " \
                "os TEXT NULLABLE, " \
                "vendor_identity TEXT NULLABLE, " \
                "ev_hostname TEXT NULLABLE,"\
                "ev_net_config TEXT NULLABLE,"\
                "ev_os TEXT NULLABLE,"\
                "ev_vendor_identity TEXT NULLABLE)"\
                #"last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " \
            )
            
        conn.commit()
        return conn

def get_cursor(conn):
    return conn.cursor()

def close_connection(conn):
    conn.close()

def execute_query(conn, query, params=None):
    cur = get_cursor(conn)
    
    if DEBUG:
        if DEBUG :
            print('='*150)
            print(f'In db connection : {conn}'\
                    f'Executing query : {query}'\
                    f'params : {params}')
            print('='*150)
            
    if params:
        cur.execute(query, params)
    else:
        cur.execute(query)
    conn.commit()
    return cur

def add_device_or_update(table, Device):
    conn = get_connection(table)
    query = f"INSERT OR REPLACE INTO [{table}] (mac_address, is_randomized_mac, hostname, net_config, os, vendor_identity, ev_hostname, ev_net_config, ev_os, ev_vendor_identity) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    params = (Device.mac_address, Device.is_randomized_mac, Device.hostname, Device.os_opt55, Device.os_ttl, Device.vendor_identity, Device.ev_hostname, Device.ev_os_opt55, Device.ev_os_ttl, Device.ev_vendor_identity)
    execute_query(conn, query, params)
    close_connection(conn)

def get_all_devices(table):
    conn = get_connection(table)
    query = f"SELECT * FROM [{table}]"
    cur = execute_query(conn, query)
    devices = cur.fetchall()
    close_connection(conn)
    return devices

def get_all_macs(table):
    conn = get_connection(table)
    query = f"SELECT mac_address FROM [{table}]"
    cur = execute_query(conn, query)
    macs = [row[0] for row in cur.fetchall()]
    close_connection(conn)
    return macs

def get_device_by_mac(table, mac_address):
    conn = get_connection(table)
    query = f"SELECT * FROM [{table}] WHERE mac_address = ?"
    cur = execute_query(conn, query, (mac_address,))
    device_data = cur.fetchone()
    close_connection(conn)
    if device_data:
        return Device(*device_data)
    return None


def main():
    pass


if __name__ == "__main__":
    main()