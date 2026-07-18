import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    target = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)  # quick, standard, deep, inventory, audit
    status = Column(String, default='running')  # running, completed, failed
    device_count = Column(Integer, default=0)
    
    devices = relationship("Device", back_populates="scan", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="scan", cascade="all, delete-orphan")


class Device(Base):
    __tablename__ = 'devices'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='SET NULL'), nullable=True)
    ip_address = Column(String, nullable=False, index=True)
    mac_address = Column(String, nullable=True, index=True)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    device_type = Column(String, default='Unknown')  # Router, Smartphone, Laptop, Desktop, Printer, IoT Device, Smart TV, Gaming Console, Unknown
    os_name = Column(String, nullable=True)
    status = Column(String, default='up')  # up, down
    first_seen = Column(DateTime, default=datetime.datetime.now)
    last_seen = Column(DateTime, default=datetime.datetime.now)
    appearance_count = Column(Integer, default=1)
    security_score = Column(Integer, default=100)
    classification_confidence = Column(String, nullable=True)
    
    scan = relationship("Scan", back_populates="devices")
    ports = relationship("Port", back_populates="device", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="device", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = 'ports'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('devices.id', ondelete='CASCADE'), nullable=False)
    port = Column(Integer, nullable=False, index=True)
    protocol = Column(String, default='tcp')
    service = Column(String, nullable=True)
    state = Column(String, default='open')  # open, closed, filtered
    risk_level = Column(String, default='Low')  # Low, Medium, High
    description = Column(Text, nullable=True)
    
    device = relationship("Device", back_populates="ports")


class Alert(Base):
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='SET NULL'), nullable=True)
    device_id = Column(Integer, ForeignKey('devices.id', ondelete='SET NULL'), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    type = Column(String, nullable=False)  # new_device, unknown_vendor, hostname_changed, mac_changed, insecure_service
    severity = Column(String, default='low')  # low, medium, high
    message = Column(Text, nullable=False)
    resolved = Column(Boolean, default=False)
    
    scan = relationship("Scan", back_populates="alerts")
    device = relationship("Device", back_populates="alerts")


class Vendor(Base):
    __tablename__ = 'vendors'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_prefix = Column(String, unique=True, index=True, nullable=False)  # e.g. "00:50:56" (uppercase)
    name = Column(String, nullable=False)


class Setting(Base):
    __tablename__ = 'settings'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String, unique=True, index=True, nullable=False)
    value = Column(String, nullable=False)
