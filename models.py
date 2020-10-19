from flask_sqlalchemy import SQLAlchemy
from threading import Thread
from pathlib import Path
from datetime import datetime
import subprocess
import shlex
import sys
import io
import json
from encoder import JsonEncodedDict

db = SQLAlchemy()


class Devices(db.Model):
    __tablename__ = 'devices'
    public_ip = db.Column(db.String(15), primary_key=True)
    device_ip = db.Column(db.String(15))
    port_status = db.Column(db.String(100))
    MAC_address = db.Column(db.String(17))
    manufacturer = db.Column(db.String(100))
    service_info = db.Column(db.String(150))
    os_details = db.Column(db.String(150))
    open_ports = db.Column(JsonEncodedDict)
    warnings = db.Column(db.String(150))

    def __init__(self, public_ip, device_ip, port_status, MAC_address, manufacturer, service_info, os_details, open_ports, warnings):
        self.public_ip = public_ip
        self.device_ip = device_ip
        self.port_status = port_status
        self.MAC_address = MAC_address
        self.manufacturer = manufacturer
        self.service_info = service_info
        self.os_details = os_details
        self.open_ports = open_ports
        self.warnings = warnings

class Network(db.Model):
    __tablename__ = 'networks'
    public_ip = db.Column(db.String(15), primary_key=True)
    ip_country = db.Column(db.String(100))
    country_cc = db.Column(db.String(5))
    gateway_ip = db.Column(db.String(15))

    def __init__(self, public_ip, ip_country, country_cc, gateway_ip):
        self.public_ip = public_ip
        self.ip_country = ip_country
        self.country_cc = country_cc
        self.gateway_ip = gateway_ip

class PacketSniffer:
    def run_tshark(self, iface):
        print("tshark test with {}.".format(iface))
        basepath = Path(__file__).parent.absolute()
        filepath = str((basepath / "packet_captures/{}.pcap".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))).resolve()).replace(" ", "_")
        
        f = open(filepath, "w+")
        f.close()
        
        cmd = "tshark -l -i " + iface + " -w " + filepath
        args = shlex.split(cmd)

        tshark = subprocess.Popen(args, stdout=subprocess.PIPE)
        #for line in io.TextIOWrapper(tshark.stdout, encoding="utf-8"):
            #print("test: %s" % line.rstrip())
            #capture_file.write("%s " % line.strip() + '\n')

    def run(self, iface):
        try:
            t = Thread(target=self.run_tshark, args=(iface, ))
            t.daemon = True
            t.start()
            t.join()
        except Exception as e:
            return str(e)
			
#class JsonEncodedType(db.TypeDecorator):
#
 #   impl = db.Text
#
 #   def process_bind_param(self, value, dialect):
  #      if value is None:
   #         return None
    #    else:
     #       return json.dumps(value)
#
 #   def process_result_value(self, value, dialect):
  #      if value is None:
   #         return {}
    #     else:
     #       return json.loads(value)

