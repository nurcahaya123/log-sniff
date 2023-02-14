import mysql.connector
from scapy.all import *

# Membuat koneksi ke database
mydb = mysql.connector.connect(
  host="localhost",
  user="username",
  password="password",
  database="db_name"
)

# Membuat kursor untuk eksekusi query
mycursor = mydb.cursor()

# Define a function to analyze ping packets
def ping_monitor(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        src_ip = pkt[IP].src
        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log = "Ping detected from source: " + src_ip
        # Menyimpan log ke database
        sql = "INSERT INTO logs (time, log) VALUES (%s, %s)"
        val = (time, log)
        mycursor.execute(sql, val)
        mydb.commit()

# Define a function to analyze DNS packets
def dns_monitor(pkt):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode()
        time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log = "DNS query detected for: " + qname
        # Menyimpan log ke database
        sql = "INSERT INTO logs (time, log) VALUES (%s, %s)"
        val = (time, log)
        mycursor.execute(sql, val)
        mydb.commit()

# Define a function to analyze HTTP packets
def http_monitor(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if b"GET" in pkt[Raw].load:
            src_ip = pkt[IP].src
            time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log = "HTTP GET request detected from source: " + src_ip
            # Menyimpan log ke database
            sql = "INSERT INTO logs (time, log) VALUES (%s, %s)"
            val = (time, log)
            mycursor.execute(sql, val)
            mydb.commit()

# Start capturing packets and analyzing them
sniff(filter="icmp or udp port 53 or tcp port 80", prn=lambda x: ping_monitor(x) or dns_monitor(x) or http_monitor(x))
