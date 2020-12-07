from flask import Flask, render_template, jsonify, request
from models import db, Network, Devices, PacketSniffer, JsonEncodedDict
from logging.handlers import RotatingFileHandler
from sqlalchemy.ext import mutable
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from threading import Thread
from pathlib import Path
from datetime import datetime
from pcapng import FileScanner
import threading
import logging
import urllib.request, urllib.parse
import webbrowser
import subprocess
import configparser
import sqlite3
import json
import re
import os
import shlex
import io
import sys
import time


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///var/database.db'
db.init_app(app)

app.secret_key = 'development-key'



def fill_entry(d, public_ip):
    port_status = ""
    MAC_address = ""
    Manufacturer = ""
    Service_info = ""
    OS_details = ""
    warnings = ""

    if (d.get("Port_status") == None):
        port_status = "none"
    else:
        port_status = d['Port_status']

    if (d.get("MAC_address") == None):
        MAC_address = "none"
    else:
        MAC_address = d['MAC_address']

    if (d.get("Manufacturer") == None):
        Manufacturer = "none"
    else:
        Manufacturer = d['Manufacturer']

    if (d.get("Service_info") == None):
        Service_info = "none"
    else:
        Service_info = d['Service_info']
    
    if (d.get("OS_details") == None):
        OS_details = "none"
    else:
        OS_details = d['OS_details']

    if (d.get("warning") == None):
        warnings = "none"
    else:
        warnings = d['warning']

    new_device = Devices(public_ip, d['IP_address'], port_status, MAC_address, Manufacturer, Service_info, OS_details, d['open_ports'], warnings)
    return(new_device)


def device_db_process(public_ip, devices):
    
    conn = sqlite3.connect("var/database.db")
    cursor = conn.cursor()

    t = (public_ip,)
        
    cursor.execute('SELECT * FROM devices WHERE public_ip = ?', t)

    device_check = cursor.fetchone()
    conn.close()
	
    if device_check == None:
        for d in devices:
            new_device = fill_entry(d, public_ip)
            db.session.add(new_device)
        db.session.commit()
        app.logger.info("Device list for {} commited to database".format(public_ip))
    else:
	#check each new devive (IP) for existing db record
	#if exists, do nothing
        conn = sqlite3.connect("var/database.db")
        cursor = conn.cursor()

        t = (public_ip,)
        cursor.execute('SELECT * FROM devices WHERE public_ip = ?', t)

        result = cursor.fetchall()
        conn.close()

        for dev in devices:
            match = 0
            for res in result:
                if (dev['IP_address'] == res[1]):
                    # TODO check MAC address and/or other attributes
                    # ESPECIALLY check for change in open ports
                    # if different then not a match
                    # replace db record with new device
                    match = 1
            if (match == 0):
                # device not in db
                # add this device to db
                new_device = fill_entry(dev, public_ip)
                db.session.add(new_device)
                app.logger.info("Network host added at {}.".format(dev['IP_address']))
            match = 0
        db.session.commit()

	# what db records are not found in device list
	# remove these from the db
        conn = sqlite3.connect("var/database.db")
        cursor = conn.cursor()

        for res in result:
            match = 0
            for dev in devices:
                if (res[1] == dev['IP_address']):
                    #print("{} is a match".format(res[1]))
                    match = 1
            if (match == 0):
                cursor.execute('DELETE FROM devices WHERE public_ip = ? AND device_ip = ?', (public_ip, res[1]))
                app.logger.info("Network host removed at {}.".format(res[1]))
                conn.commit()
            match = 0
        conn.close()


@app.route("/", methods=['GET', 'POST'])
def index():

    # GET PUBLIC IP & COUNTRY INFO 
    myip_url = 'https://api.myip.com'
    g = urllib.request.urlopen(myip_url)
    myip_results = g.read()
    g.close()

    myip_data = json.loads(myip_results)
    
    # GET DEFAULT GATEWAY
    netstat_req = subprocess.Popen("ip r | grep default", shell=True, stdout=subprocess.PIPE)
    gateway_ip = str(netstat_req.communicate()[0])
    gateway_ip = str(re.findall( r'[0-9]+(?:\.[0-9]+){3}', gateway_ip))[2:-2]
    
    # CHECK DB FOR EXISTING PUBLIC IPT
    sql_conn = sqlite3.connect("var/database.db")
    cursor = sql_conn.cursor()
    
    t = (myip_data['ip'],)
    cursor.execute('SELECT public_ip FROM networks WHERE public_ip = ?', t)

    db_result = cursor.fetchone()

    sql_conn.close()
    
    # IF NOT FOUND THEN ADD NEW NETWORK RECORD TO DB
    if db_result == None:
        new_network = Network(myip_data['ip'], myip_data['country'], myip_data['cc'], gateway_ip)
        db.session.add(new_network)
        db.session.commit()
    

    conn = sqlite3.connect("var/database.db")
    cursor = conn.cursor()

    t = (myip_data['ip'],)
        
    cursor.execute('SELECT * FROM devices WHERE public_ip = ?', t)

    device_result = cursor.fetchone()

    if device_result != None:
        device_list = []
        device_list.append(device_result)

        for row in cursor:
            device_list.append(row)

        conn.close()

        return render_template("dashboard.html", public_ip=myip_data, gateway_ip=gateway_ip, devices=device_list)
    else:
        conn.close()
    
    return render_template("dashboard.html", public_ip=myip_data, gateway_ip=gateway_ip)


@app.route('/device_scan')
def device_scan():
    try:
        # TODO GET IPS FROM DATABASE SELECT

        public_ip = request.args.get('public_ip', 0, type=str)
        gateway_ip = request.args.get('gateway_ip', 0, type=str)

        netstat_req = subprocess.Popen("ipcalc {}".format(gateway_ip), shell=True, stdout=subprocess.PIPE)

        lines = netstat_req.stdout.read().splitlines()

        data = []

        count = 0
        for each in lines:
            temp = each.decode('utf-8').replace("'", '"')
            temp = ' '.join(temp.split())
            temp += '\n'
            lines[count] = temp

            temp_data = []
            temp_str = ""
            for i in range(len(lines[count])):
                if lines[count][i] == " " or lines[count][i] == '\n':
                    temp_data.append(temp_str)
                    temp_str = ""
                temp_str += lines[count][i]
            data.append(temp_data)
            temp_data = []
            count += 1

        del data[3] 
        del data[1] 
        del data[1]
        del data[5]
        del data[5]

        key = []
        value = []

        count = 0
        for each in data:
            del data[count][2:]
            data[count][0] = data[count][0][:-1]
            key.append(data[count][0])
            value.append(data[count][1])
            count += 1

        ipcalc_dict = dict(zip(key, value))
        # DICT HOLDS:
        #   Address
        #   Network
        #   HostMin
        #   HostMax
        #   Broadcast

        netstat_req = subprocess.Popen("sudo nmap -sn {} | grep Nmap".format(ipcalc_dict['Network']), shell=True, stdout=subprocess.PIPE)
        lines = netstat_req.stdout.read().splitlines()

        ip_addresses = []

        for each in lines:
            temp = each.decode('utf-8').replace("'", '"')
            #print(temp)
            if temp[:4] == "Nmap":
                #print(temp)
                ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', temp )
                if len(ip) > 0:
                    ip = str(ip)[2:-2]
                    ip_addresses.append(ip)

	# Remove ip for Raspberry Pi host device
        netstat_req = subprocess.Popen("ip r | grep src", shell=True, stdout=subprocess.PIPE)
        this_ip = str(netstat_req.communicate()[0])
        this_ip = str(re.findall( r'[0-9]+(?:\.[0-9]+){3}', this_ip))[17:-2]

        for ip in ip_addresses:
            if this_ip in ip_addresses:
                ip_addresses.remove(this_ip)

        app.logger.info("Network scan for {} hosts: {}".format(len(ip_addresses), ip_addresses))

        devices = []
        # DICT FOR EACH DEVICE HOLDS:
        #   IP_address
        #   Port_status
        #   MAC_address
        #   Manufacturer
        #   Service_Info??
        #   OS_details??
        #   open_ports
        #   | awk '/PORT|ports|open|MAC|fingerprints|Service Info|OS details/'

        count = 1
        for each in ip_addresses:
            netstat_req = subprocess.Popen("sudo nmap -sV -O {} ".format(each), shell=True, stdout=subprocess.PIPE)
            lines = netstat_req.stdout.read().splitlines()

            device = []
    
            key = []
            value = []
            port_info = []

            key.append("IP_address")
            value.append(each)
            for each in lines:
                temp = each.decode('utf-8').replace("'", '"')
                if temp[:9] == "Not shown":
                    key.append("Port_status")
                    value.append(temp[11:])
                elif temp[:3] == "All":
                    key.append("Port_status")
                    value.append(temp)
                elif temp[:4] == "PORT" or ("open" in temp):
                    port_info.append(temp)
                elif temp[:3] == "MAC":
                    p = re.compile(r'(?:[0-9a-fA-F]:?){12}')
                    mac = re.findall(p, temp)
                    mac = str(mac)[2:-2]
                    key.append("MAC_address")
                    value.append(mac)

                    name = re.search('\(([^)]+)', temp).group(1)
                    key.append("Manufacturer")
                    value.append(name)
                elif temp[:12] == "Service Info":
                    key.append("Service_Info")
                    value.append(temp[14:])
                elif temp[:10] == "OS_details":
                    key.append("OS_details")
                    value.append(temp[12:])
                elif "fingerprints" in temp:
                    key.append("OS_details")
                    value.append(temp)

            device = dict(zip(key, value))

            

            headers = []
            ports = []
            warning = ""
    
            head = 0
            tail = None
            
            if port_info != []:
                i = 0
                for each in port_info:
                    if each[:7] == "Warning":
                        warning = each
                        continue
                    temp = []
                    port_info[i] = ' '.join(each.split())
                    for e, l in enumerate(port_info[i]):
                        if i == 0:
                            if l == " ":
                                headers.append(port_info[i][tail:head])
                                tail = head + 1
                            elif l == port_info[i][-1]:
                                head += 1
                                headers.append(port_info[i][tail:head])
                                head -= 1
                        else:
                             if l == " ":
                                 if len(temp) == 3:
                                     temp.append(port_info[i][tail:head])
                                     ports.append(temp)
                                     break
                                 else:
                                     temp.append(port_info[i][tail:head])
                                     tail = head + 1
                        head += 1
                    i += 1
                    head = 0
                    tail = None
                    
            else:
                ports.append("No open ports")

            open_ports = []
            
            if ports[0] == "No open ports":
                s = []
                s.append("No open ports")
                nein = dict(zip("1", s)
                        )
                device.update(dict(open_ports = nein))
            else:
                for each in ports:
                    p = dict(zip(headers, each))
                    open_ports.append(p)

                ct = 1
                ids = []
                for each in open_ports:
                    ids.append(str(ct))
                    ct += 1

                ports_open = dict(zip(ids, open_ports))

                device.update(dict(open_ports = ports_open))
                if len(warning) > 0:
                    device.update(dict(warning = warning))
                #last_scan = datetime.datetime.now().replace(second=0, microsecond=0)
                #device.update(dict(last_scan = last_scan))
                #print(last_scan)

            devices.append(device)

            scan_percent = count / len(ip_addresses) * 100
            print("Device scan {}% complete".format(round(scan_percent), 1))

            count += 1

        device_db_process(public_ip, devices)
       
        return jsonify(device_list=devices)

    except Exception as e:
        return str(e)

@app.route('/packet_sniff')
def sniff():
    iface = 'wlan0'

    basepath = Path(__file__).parent.absolute()
    filepath = str((basepath / "packet_captures/{}.pcap".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))).resolve()).replace(" ", "_")
    
    args = []
    args.append(iface)
    args.append(filepath)
    sniffer = PacketSniffer()
    sniffer.run(args)
    
    print("Sniffer thread initialised.")

    time.sleep(30)

    cmd = "tshark -r " + filepath
    run_args = shlex.split(cmd)

    txt_file = filepath[:-4] + "txt"
    

    f = open(txt_file, "w+")


    file_lines = 0
    count = 0

    with open(filepath, 'rb') as fp:
        scanner = FileScanner(fp)
        for block in scanner:
            print(block.PacketDataField)
        #tshark = subprocess.Popen(run_args, stdout=subprocess.PIPE)
        #for line in io.TextIOWrapper(tshark.stdout, encoding="utf-8"):
            #print("test: %s" % line.rstrip())
            #f.write(line.rstrip() + "\n")
            #count = len(scanner.readlines())
            #print("COUNT: ", count)
            #if (file_lines == count): 
                #time.sleep(5)

    return jsonify(filepath[:4])



@app.route('/icons')
def icons():
    return render_template("icons.html")

@app.route('/notifications')
def notifications():
    return render_template("notifications.html")

@app.route('/upgrade')
def upgrade():
    return render_template("upgrade.html")

@app.route('/user')
def user():
    return render_template("user.html")
    


def init(app):
    config = configparser.ConfigParser() 
    try:
        config_location = "etc/defaults.cfg"
        config.read(config_location)
        
        app.config['SERVER_NAME'] = config.get('config', 'server')
        app.config['DEBUG'] = config.get('config', 'debug')
        app.config['LOG_FILE'] = config.get('logging', 'name')
        app.config['LOG_LOCATION'] = config.get('logging', 'location')
        app.config['LOG_LEVEL'] = config.get('logging', 'level')

    except:
        print("Could not read configs from: ", config_location)


def logs(app):
    log_pathname = app.config['LOG_LOCATION'] + app.config['LOG_FILE']
    file_handler = RotatingFileHandler(log_pathname, maxBytes=1024*1024*10, backupCount=1024)
    file_handler.setLevel(app.config['LOG_LEVEL'])
    formatter = logging.Formatter("%(levelname)s | %(asctime)s | %(module)s | %(funcName)s | %(message)s")
    file_handler.setFormatter(formatter)
    app.logger.setLevel(app.config['LOG_LEVEL'])
    app.logger.addHandler(file_handler)


if __name__ == "__main__":
    init(app)
    logs(app) 
    webbrowser.open(app.config['SERVER_NAME'])
    app.run(debug=app.config['DEBUG'],
            use_reloader=False)
