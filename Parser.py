import mysql.connector
from mysql.connector import errorcode

# Log file paths
LOG_FILES = {
    'Suspicious_Port': r'C:\Mini-SIEM\Suspicious_Port.txt',
    'Ping_Sweep': r'C:\Mini-SIEM\Ping_Sweep.txt',
    'Port_Scan': r'C:\Mini-SIEM\Port_Scan.txt'
}

PORTS = {
    '21': 'FTP', '22': 'SSH', '23': 'TELNET', '25': 'SMTP', '67': 'DHCP', '53': 'DNS', '80': 'HTTP',
    '445': 'SMB', '443': 'HTTPS'
}

# Database configuration
USER = ''
PASSWORD = ''
HOST = ''
DATABASE = ''

def connect_to_db():
    """Connect to the MySQL database."""
    try:
        cnx = mysql.connector.connect(user=USER, password=PASSWORD, host=HOST, database=DATABASE)
        return cnx, cnx.cursor(buffered=True)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Error: Incorrect username or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Error: Database does not exist")
        else:
            print(f"Error: {err}")
        return None

def log_file_to_dict(path):
    """Convert log file lines into a list of dictionaries."""
    with open(path, 'r') as file:
        lines = [line.split() for line in file]
    return [{'DATE': f"{line[0]} {line[1]}", 'SRC_IP': line[2], 'DST_IP': line[3], 'PORT': line[4], 'ACTION': line[5]}
            for line in lines]

def add_protocol(lst_dicts):
    """Add protocol information based on port numbers."""
    for dic in lst_dicts:
        dic['PROTOCOL'] = PORTS.get(dic['PORT'], 'Unknown')
    return lst_dicts

def insert_to_db(log, cnx, cursor):
    """Insert log entry into the database."""
    query = """INSERT INTO fwlogs (ID, DATE, SRC_IP, DST_IP, PORT, PROTOCOL, ACTION) 
               VALUES (NULL, %(DATE)s, %(SRC_IP)s, %(DST_IP)s, %(PORT)s, %(PROTOCOL)s, %(ACTION)s)"""
    cursor.execute(query, log)
    cnx.commit()

def reset_db():
    """Reset the database by clearing the 'fwlogs' table."""
    cnx, cursor = connect_to_db()
    if cnx:
        cursor.execute('DELETE FROM fwlogs')
        cnx.commit()
        cursor.close()
        cnx.close()

def main():
    """Main function to process logs and insert data into the database."""
    reset_db()  # Clear the database first

    # Connect to the database
    cnx, cursor = connect_to_db()
    if not cnx:
        return

    # Process and insert Ping Sweep log data
    for log in add_protocol(log_file_to_dict(LOG_FILES['Ping_Sweep'])):
        insert_to_db(log, cnx, cursor)

    # Check number of entries in the database
    cursor.execute("SELECT COUNT(*) FROM fwlogs")
    print(f"Total records in fwlogs: {cursor.fetchone()[0]}")

    cursor.close()
    cnx.close()

if __name__ == '__main__':
    main()
