import dpkt
import logging
import socket

    
class TcpStreamException(Exception):
    def __init__(self, value):
         self.value = value
    def __str__(self):
         return repr(self.value)

class TcpStream:
    
    _cnt = 0
    
    def __init__(self, tcp, ip):
        self.closed = False
        self.data = ""
        self.gaps = []

        self.seq = tcp.seq
        self.start_seq = tcp.seq

        # id each stream
        self.id = self._cnt
        TcpStream._cnt += 1
        logging.debug("created (%i): seq:0 (%i)" % (self.id, self.seq))
        
        if not tcp.flags & dpkt.tcp.TH_SYN:
            logging.warning("received (%i): non SYN first segment - src:%s dst:%s sprt:%i dort:%i" % \
                (self.id, socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), tcp.sport, tcp.dport))
    

        
    def receive(self, tcp):
        rel = tcp.seq - self.seq
        logging.debug("received (%i): bytes: %i, expected seq:%i (%i), actual seq:%i (%i)" \
            % (self.id, len(tcp.data), self.seq, self._rel(self.seq), tcp.seq, self._rel(tcp.seq)))
        
        if self.seq == tcp.seq:
            self.data += tcp.data
            logging.debug("received: (%i): in sequence" % self.id)
        elif self.seq > tcp.seq:
            logging.warning("received (%i): ealier segment - expected:%i (%i) received:%i (%i) size:%i, ignored" % \
                (self.id, self.seq, self._rel(self.seq), tcp.seq, self._rel(tcp.seq), len(tcp.data)))
            return
        else:
            # earlier segment missing, adding filler
            delta = tcp.seq-self.seq
            logging.warning("received (%i): previous segment missing - expected:%i (%i) received:%i (%i) delta:%i, adding filler" % \
                (self.id, self.seq, self._rel(self.seq), tcp.seq, self._rel(tcp.seq), delta))
            self.gaps.append(())
            filler = b'\0' * (tcp.seq-self.seq)
            #filler = array('b', )
            self.data += filler
            self.seq += len(filler)
        
        # follow other sides seq number
        # move seq 1 if SYN or FIN is set
        if tcp.flags & dpkt.tcp.TH_SYN or tcp.flags & dpkt.tcp.TH_FIN:
            self.seq += 1
            #print "received (%i): moved seq 1" % self.id
        self.seq += len(tcp.data)
        
        if tcp.flags & dpkt.tcp.TH_FIN:
            logging.debug("closed (%i)" % self.id)
            self.closed = True

    def _rel(self, seq):
        return seq - self.start_seq

class TcpStreamParser:
    
    #def __init__(self):
    
    def parse_pcap_file(self, filename):
        # Open the pcap file
        f = open(filename, 'rb')
        pcap = dpkt.pcap.Reader(f)
    
        streams = dict()
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
        
            # ignore non IP frames
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
        
            # ignore non TCP packets
            ip = eth.data
            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue
        
            tcp = ip.data
            tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)
        
            if tupl not in streams:
                streams[tupl] = TcpStream(tcp, ip)
            streams[tupl].receive(tcp)
        
        return streams


if __name__ == '__main__':
    import sys
    if len(sys.argv) <= 1:
        print "%s <pcap filename>" % sys.argv[0]
        sys.exit(2)
    
    #logging.basicConfig(level=logging.DEBUG,format="%(levelname)s: %(message)s")
    logging.basicConfig(level=logging.INFO,format="%(levelname)s: %(message)s")

    parser = TcpStreamParser()
    streams = parser.parse_pcap_file(sys.argv[1])
