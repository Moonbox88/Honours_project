from flask_sqlalchemy import SQLAlchemy
from threading import Thread
import subprocess
import shlex
import sys
import io
import json
from encoder import JsonEncodedDict
from pathlib import Path
from datetime import datetime

db = SQLAlchemy()


class Devices(db.Model):
    __tablename__ = 'devices'
    public_ip = db.Column(db.String(15), db.ForeignKey('networks.public_ip'))
    device_ip = db.Column(db.String(15), primary_key=True)
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
    def run_tshark(self, args):
        print("tshark test with {}.".format(args[0]))

        filepath = args[1]

        cmd = "tshark -l -i " + args[0] + " -w " + filepath
        run_args = shlex.split(cmd)

        tshark = subprocess.Popen(run_args, stdout=subprocess.PIPE)


    def run(self, args):
        try:
            t = Thread(target=self.run_tshark, args=(args, ))
            t.daemon = True
            t.start()
            t.join()
        except Exception as e:
            return str(e)


