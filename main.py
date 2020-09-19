from flask import Flask, render_template, jsonify, request
from models import db, Network
from logging.handlers import RotatingFileHandler
import urllib.request, urllib.parse
import webbrowser
import subprocess
import configparser
import sqlite3
import json
import re
import logging


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///var/database.db'
db.init_app(app)

app.secret_key = 'development-key'

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
    
    # CHECK DB FOR EXISTING PUBLIC IP
    sql_conn = sqlite3.connect("var/database.db")
    cursor = sql_conn.cursor()
    
    t = (myip_data['ip'],)
    ip_db_check = cursor.execute('SELECT public_ip FROM networks WHERE public_ip = ?', t)

    db_result = cursor.fetchone()
    sql_conn.close()
    
    # IF NOT FOUND THEN ADD NEW NETWORK RECORD TO DB
    if db_result == None:
        new_network = Network(myip_data['ip'], myip_data['country'], myip_data['cc'], gateway_ip)
        db.session.add(new_network)
        db.session.commit()
    
    return render_template("dashboard.html", public_ip=myip_data, gateway_ip=gateway_ip)


@app.route('/device_scan')
def device_scan():
    try:
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

        app.logger.info("{} network hosts discovered".format(len(ip_addresses)))

        devices = []
        # DICT FOR EACH DEVICE HOLDS:
        #   IP_address
        #   Port_status
        #   MAC_address
        #   Manufacturer
        #   Service_Info??
        #   OS_details??

        count = 1
        for each in ip_addresses:
            netstat_req = subprocess.Popen("sudo nmap -sV -O {} | awk '/PORT|ports|open|MAC|fingerprints|Service Info|OS details/'".format(each), shell=True, stdout=subprocess.PIPE)
            lines = netstat_req.stdout.read().splitlines()

            device = []
    
            key = []
            value = []
            port_info = []

            #print("\nDEVICE {}\n".format(count))
            key.append("IP_address")
            value.append(each)
            for each in lines:
                temp = each.decode('utf-8').replace("'", '"')
                #print(temp)
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
            devices.append(device)

            scan_percent = count / len(ip_addresses) * 100
            app.logger.info("Device scan {}% complete".format(scan_percent))

            count += 1

        return jsonify(device_list=devices)

    except Exception as e:
        return str(e)


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
