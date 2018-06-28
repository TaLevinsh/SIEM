import mysql.connector
from mysql.connector import errorcode

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
            print('Something is wrong with your user name or password')
        elif Err.errno == errorcode.ER_BAD_DB_ERROR:
            print('Database does not exist')
        else:
            print(Err)
        return None


def SpecificPort():
    Cnx, Cursor = ConnectToDB()
    Query = 'SELECT SRC_IP FROM fwlogs WHERE PORT=444 OR PORT=4445'
    Cursor.execute(Query)
    IP_Lst = []
    for IP in Cursor:
        if IP not in IP_Lst:
            IP_Lst.append(IP)
    if len(IP_Lst) > 0:
        print 'These IP addresses:', IP_Lst, 'attempted to connect suspicious ports (444 / 4445)'
    elif len(IP_Lst) == 0:
        print 'No suspicious port attack'
    Cnx.commit()
    Cursor.close()
    Cnx.close()


def PortScan():
    Cnx, Cursor = ConnectToDB()
    Query1 = 'SELECT SRC_IP FROM fwlogs'
    Cursor.execute(Query1)
    IP_Lst = []
    for IP in Cursor:
        if IP not in IP_Lst:
            IP_Lst.append(IP)
    New_IP_Lst = []
    for Item in IP_Lst:
        New_IP = "".join(Item)
        if New_IP not in New_IP_Lst:
            New_IP_Lst.append(New_IP)
    for New_IP in New_IP_Lst:
        Query2 = 'SELECT COUNT(DISTINCT PORT) FROM fwlogs WHERE SRC_IP=' + "'" + New_IP + "'"
        Cursor.execute(Query2)
        for Ports_Num1 in Cursor:
            Ports_Num2 = int(Ports_Num1[0])
            if Ports_Num2 >= 10:
                print 'This IP Address', New_IP, 'Attempted To Connect To', Ports_Num1, 'Different Ports'
    else:
        print 'No Port-Scan Attack'
    Cnx.commit()
    Cursor.close()
    Cnx.close()


def PingSweep():
    Cnx, Cursor = ConnectToDB()
    Query1 = 'SELECT SRC_IP FROM fwlogs'
    Cursor.execute(Query1)
    IP_Lst = []
    for IP in Cursor:
        if IP not in IP_Lst:
            IP_Lst.append(IP)
    New_IP_Lst = []
    for Item in IP_Lst:
        New_IP = "".join(Item)
        if New_IP not in New_IP_Lst:
            New_IP_Lst.append(New_IP)
    for New_IP in New_IP_Lst:
        Query2 = 'SELECT COUNT(DISTINCT DST_IP) FROM fwlogs WHERE SRC_IP=' + "'" + New_IP + "'" + 'AND PORT=0'
        Cursor.execute(Query2)
        for Dst_IP1 in Cursor:
            Dst_IP2 = int(Dst_IP1[0])
            if Dst_IP2 >= 10:
                print 'This IP Address', New_IP, 'Attempted To Ping', Dst_IP1, 'Different Hosts'
    else:
        print 'No Ping-Sweep Attack'
    Cnx.commit()
    Cursor.close()
    Cnx.close()


def GetTimeDifferences(Start, End):
    C = End - Start
    return divmod(C.days * 86400 + C.seconds, 60)


def PingSweepTime():
    Cnx, Cursor = ConnectToDB()
    Query1 = 'SELECT SRC_IP FROM fwlogs'
    Cursor.execute(Query1)
    IP_Lst = []
    for IP in Cursor:
        if IP not in IP_Lst:
            IP_Lst.append(IP)
    New_IP_Lst = []
    for Item in IP_Lst:
        New_IP = "".join(Item)
        if New_IP not in New_IP_Lst:
            New_IP_Lst.append(New_IP)
    for New_IP in New_IP_Lst:
        Query2 = 'SELECT DISTINCT (DST_IP), DATE FROM fwlogs WHERE SRC_IP=' + "'" + New_IP + "'" + 'ORDER BY DATE DESC LIMIT 1'     # MAX
        Cursor.execute(Query2)
        TIME_LST = []
        for MaxTIME in Cursor:
            MaxTIME1 = MaxTIME[1]
            if MaxTIME1 not in TIME_LST:
                TIME_LST.append(MaxTIME1)
        Query3 = 'SELECT DISTINCT (DST_IP), DATE FROM fwlogs WHERE SRC_IP=' + "'" + New_IP + "'" + 'ORDER BY DATE LIMIT 1'     # MIN
        Cursor.execute(Query3)
        for MinTIME in Cursor:
            MinTIME1 = MinTIME[1]
            if MinTIME1 not in TIME_LST:
                TIME_LST.append(MinTIME1)

            TimeDifference = GetTimeDifferences(TIME_LST[1], TIME_LST[0])
            if TimeDifference <= (0, 10):
                Query4 = 'SELECT COUNT(DISTINCT DST_IP) FROM fwlogs WHERE SRC_IP=' + "'" + New_IP + "'" + 'AND PORT=0'
                Cursor.execute(Query4)
                for Dst_IP1 in Cursor:
                    Dst_IP2 = int(Dst_IP1[0])
                    if Dst_IP2 >= 10:
                        print 'This IP Address', New_IP, 'Attempted To Ping', Dst_IP1, 'Different Hosts In Less Than 10 Seconds'
            else:
                print 'No Ping-Sweep Attack In Less Than 10 Seconds'
    Cnx.commit()
    Cursor.close()
    Cnx.close()


def main():
    Cnx, Cursor = ConnectToDB()

    SpecificPort()
    PortScan()
    PingSweep()
    PingSweepTime()

    Cursor.close()
    Cnx.close()


if __name__ == '__main__':
    main()
