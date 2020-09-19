
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


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
