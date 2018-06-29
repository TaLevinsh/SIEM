import mysql.connector
from mysql.connector import errorcode


# Log files;
Suspicious_Port_LogFile = r'C:\Mini-SIEM\Suspicious_Port.txt'
Ping_Sweep_LogFile = r'C:\Mini-SIEM\Ping_Sweep.txt'
Port_Scan_LogFile = r'C:\Mini-SIEM\Port_Scan.txt'

Ports = {'21': 'FTP', '22': 'SSH', '23': 'TELNET', '25': 'SMTP', '67': 'DHCP', '53': 'DNS', '80': 'HTTP', '445': 'SMB',
         '443': 'HTTPS'}


def LogFileToDict(Path):
    with open(Path, 'r') as Opened_File:
        Lst_Lines = []
        Lst_Dicts = []
        for Line in Opened_File:
            Lst_Lines.append(Line.split())
        for Item in Lst_Lines:
            New_Dict = {'DATE': Item[0] + ' ' + Item[1], 'SRC_IP': Item[2], 'DST_IP': Item[3], 'PORT': Item[4],
                            'ACTION': Item[5]}
            Lst_Dicts.append(New_Dict)
        return Lst_Dicts


def PortToProtocol(Dict):
    Proto = Dict['PORT']
    if Proto in Ports:
        Dict['PROTOCOL'] = Ports[Proto]
    else:
        Dict['PROTOCOL'] = 'Unknown'
    return Dict


def AddProtocol(Lst_Dicts):
    New_Lst_Dicts = []
    for Dict in Lst_Dicts:
        New_Lst_Dicts.append(PortToProtocol(Dict))
    return New_Lst_Dicts


User = 'root'
Password = 'P@ssw0rd'
Host = '192.168.191.129'
Database = 'Siem'


def ConnectToDB():
    try:
        Cnx = mysql.connector.connect(user=User, password=Password,
                                      host=Host, database=Database)
        return Cnx, Cnx.cursor(buffered=True)
    except mysql.connector.Error as Err:
        if Err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif Err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(Err)
        return None


def InsertToDB(Log, Cnx, Cursor):
    Add_Log = ("""INSERT INTO fwlogs (ID, DATE, SRC_IP, DST_IP, PORT, PROTOCOL, ACTION) VALUES (NULL, %(DATE)s, 
    %(SRC_IP)s, %(DST_IP)s, %(PORT)s, %(PROTOCOL)s, %(ACTION)s)""")
    Cursor.execute(Add_Log, Log)
    Cnx.commit()


def ResetDB():
    Cnx, Cursor = ConnectToDB()
    Cursor.execute('DELETE FROM fwlogs')
    Cnx.commit()
    Cursor.close()
    Cnx.close()


def main():
    ResetDB()
    Cnx, Cursor = ConnectToDB()
    for Dic in AddProtocol(LogFileToDict(Ping_Sweep_LogFile)):
        InsertToDB(Dic, Cnx, Cursor)

    # Check;
    Query = "SELECT COUNT(*) FROM fwlogs"
    Cursor.execute(Query)
    print Cursor.fetchone()

    Cursor.close()
    Cnx.close()


if __name__ == '__main__':
    main()
