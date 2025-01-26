import mysql.connector
from mysql.connector import errorcode


# Database configuration
USER = ''
PASSWORD = ''
HOST = ''
DATABASE = ''

def connect_to_db():
    """Connect to MySQL database and return the connection and cursor."""
    try:
        cnx = mysql.connector.connect(user=USER, password=PASSWORD, host=HOST, database=DATABASE)
        return cnx, cnx.cursor(buffered=True)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print('Access denied: Check your username or password')
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print('Database does not exist')
        else:
            print(f"Error: {err}")
        return None


def fetch_distinct_ips(cursor):
    """Fetch distinct source IPs from the firewall logs."""
    cursor.execute('SELECT DISTINCT SRC_IP FROM fwlogs')
    return [item[0] for item in cursor.fetchall()]


def specific_port():
    """Detect attempts to connect to suspicious ports (444/4445)."""
    cnx, cursor = connect_to_db()
    if cnx is None:
        return

    query = 'SELECT SRC_IP FROM fwlogs WHERE PORT IN (444, 4445)'
    cursor.execute(query)
    ip_list = [item[0] for item in cursor.fetchall()]

    if ip_list:
        print(f"These IP addresses attempted to connect to suspicious ports (444 / 4445): {ip_list}")
    else:
        print("No suspicious port attack detected.")
    
    cursor.close()
    cnx.close()


def port_scan():
    """Detect port scan attempts (multiple distinct ports from the same IP)."""
    cnx, cursor = connect_to_db()
    if cnx is None:
        return

    ip_list = fetch_distinct_ips(cursor)
    
    for ip in ip_list:
        query = f'SELECT COUNT(DISTINCT PORT) FROM fwlogs WHERE SRC_IP="{ip}"'
        cursor.execute(query)
        port_count = cursor.fetchone()[0]

        if port_count >= 10:
            print(f"IP {ip} attempted to connect to {port_count} different ports.")
    
    cursor.close()
    cnx.close()


def ping_sweep():
    """Detect ping sweep attempts (same source IP pinging multiple destinations)."""
    cnx, cursor = connect_to_db()
    if cnx is None:
        return

    ip_list = fetch_distinct_ips(cursor)
    
    for ip in ip_list:
        query = f'SELECT COUNT(DISTINCT DST_IP) FROM fwlogs WHERE SRC_IP="{ip}" AND PORT=0'
        cursor.execute(query)
        dst_count = cursor.fetchone()[0]

        if dst_count >= 10:
            print(f"IP {ip} attempted to ping {dst_count} different hosts.")
    
    cursor.close()
    cnx.close()


def ping_sweep_time():
    """Detect rapid ping sweeps (same source IP pinging multiple destinations in under 10 seconds)."""
    cnx, cursor = connect_to_db()
    if cnx is None:
        return

    ip_list = fetch_distinct_ips(cursor)
    
    for ip in ip_list:
        query_max = f'SELECT DISTINCT DST_IP, DATE FROM fwlogs WHERE SRC_IP="{ip}" ORDER BY DATE DESC LIMIT 1'
        query_min = f'SELECT DISTINCT DST_IP, DATE FROM fwlogs WHERE SRC_IP="{ip}" ORDER BY DATE LIMIT 1'
        
        cursor.execute(query_max)
        max_time = cursor.fetchone()[1]  # Latest timestamp

        cursor.execute(query_min)
        min_time = cursor.fetchone()[1]  # Earliest timestamp

        time_difference = get_time_difference(min_time, max_time)

        if time_difference <= (0, 10):  # Less than 10 seconds
            query = f'SELECT COUNT(DISTINCT DST_IP) FROM fwlogs WHERE SRC_IP="{ip}" AND PORT=0'
            cursor.execute(query)
            dst_count = cursor.fetchone()[0]

            if dst_count >= 10:
                print(f"IP {ip} attempted to ping {dst_count} different hosts in less than 10 seconds.")
    
    cursor.close()
    cnx.close()


def get_time_difference(start, end):
    """Calculate the time difference between two datetime objects."""
    delta = end - start
    return divmod(delta.days * 86400 + delta.seconds, 60)


def main():
    """Main function to run all detection checks."""
    specific_port()
    port_scan()
    ping_sweep()
    ping_sweep_time()


if __name__ == '__main__':
    main()
