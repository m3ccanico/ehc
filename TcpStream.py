import dpkt
    
class TcpStreamException(Exception):
    def __init__(self, value):
         self.value = value
    def __str__(self):
         return repr(self.value)

class TcpStream:
    
    _cnt = 0
    
    def __init__(self, tcp, ip, debug=False):
        #self.src_ip = ip.src
        #self.dst_ip = ip.dst
        #self.src_prt = tcp.sport
        #self.dst_prt = tcp.dport
        self.debug = debug
        self.closed = False
        self.data = ""
        
        if tcp.flags & dpkt.tcp.TH_SYN:
            self.seq = tcp.seq
        else:
            raise TcpStreamException("out of sync SYN")
        
        # id each stream
        self.id = self._cnt
        TcpStream._cnt += 1
        self._debug("created (%i): seq:0 (%i)" % (self.id, self.seq))
        
        
    def _debug(self, message):
        if self.debug:
            print message
        
    def receive(self, tcp):
        rel = tcp.seq - self.seq
        self._debug("received (%i): bytes: %i, expected seq:%i, actual seq:%i" \
            % (self.id, len(tcp.data), self.seq, tcp.seq))
        
        if self.seq == tcp.seq:
            self.data += tcp.data
        elif self.seq > tcp.seq:
            self._debug("received (%i): retransmission (expected:%i received:%i)" % (self.id, self.seq, tcp.seq))
        else:
            raise TcpStreamException("out of sequence segment received (expected:%i received:%i)" % (self.seq, tcp.seq))
        
        # follow other sides seq number
        # move seq 1 if SYN or FIN is set
        if tcp.flags & dpkt.tcp.TH_SYN or tcp.flags & dpkt.tcp.TH_FIN:
            self.seq += 1
            #print "received (%i): moved seq 1" % self.id
        self.seq += len(tcp.data)
        
        if tcp.flags & dpkt.tcp.TH_FIN:
            self._debug("closed (%i)" % self.id)
            self.closed = True

class TcpStreamParser:
    
    def __init__(self, debug=False):
        self.debug = debug
    
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
                streams[tupl] = TcpStream(tcp, ip, debug=self.debug)
            streams[tupl].receive(tcp)
        
        return streams


if __name__ == '__main__':
    import sys
    if len(sys.argv) <= 1:
        print "%s <pcap filename>" % sys.argv[0]
        sys.exit(2)
    
    parser = TcpStreamParser(debug=False)
    streams = parser.parse_pcap_file(sys.argv[1])
