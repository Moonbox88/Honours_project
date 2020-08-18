from flask import Flask, render_template
import urllib.request, urllib.parse
import webbrowser
import subprocess
import configparser
import json
import re

app = Flask(__name__)


@app.route("/")
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
    gateway = []

    count = 0
    element = ""
    for i in gateway_ip:
        element += i
        if i == " ":
            gateway.append(element)
            element = ""

    gateway_ip = gateway[2]

    # GET NETWORK DETAILS
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

    netstat_req = subprocess.Popen("sudo nmap -F {} | grep 'Nmap\|MAC'".format(ipcalc_dict['Network']), shell=True, stdout=subprocess.PIPE)
    lines = netstat_req.stdout.read().splitlines()

    ip_addresses = []
    MAC_addresses = []

    for each in lines:
        temp = each.decode('utf-8').replace("'", '"')
        if temp[0] == 'N':
            ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', temp )
            ip_addresses.append(ip)
        elif temp[0] == 'M':
            p = re.compile(r'(?:[0-9a-fA-F]:?){12}')
            mac = re.findall(p, temp)
            MAC_addresses.append(mac)

    del ip_addresses[-1]

    devices = []
    count = 0
    for each in ip_addresses:
        device = []
        device.append(ip_addresses[count])
        if len(MAC_addresses) > count:
            device.append(MAC_addresses[count])
        else:
            device.append("No MAC found")
        devices.append(device)
        count += 1



    return render_template("dashboard.html", public_ip=myip_data, gateway_ip=gateway_ip, devices=devices)


def init(app):
    config = configparser.ConfigParser()
    try:
        config_location = "etc/defaults.cfg"
        config.read(config_location)
        
        app.config['SERVER_NAME'] = config.get('config', 'server')
        app.config['DEBUG'] = config.get("config", "debug")
    except:
        print("Could not read configs from: ", config_location)

if __name__ == "__main__":
    init(app)
    webbrowser.open(app.config['SERVER_NAME'])
    app.run(debug=app.config['DEBUG'],
            use_reloader=False)
