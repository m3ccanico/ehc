import nids
import sys

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

def http_callback(tcp):
    #print "http"
    #print tcp.client.data[:tcp.client.count]
    print tcp.client.data[:20]

def tcp_callback(tcp):
    #print "tcps -", str(tcp.addr), " state:", tcp.nids_state
    if tcp.nids_state == nids.NIDS_JUST_EST:
        # new to us, but do we care?
        ((src, sport), (dst, dport)) = tcp.addr
        #print tcp.addr
        if dport in (80, 8000, 8080):
            #print "collecting..."
            tcp.client.collect = 1
            tcp.server.collect = 1
    elif tcp.nids_state == nids.NIDS_DATA:
        # keep all of the stream's new data
        tcp.discard(0)
    elif tcp.nids_state in end_states:
        http_callback(tcp)
        #print "addr:", tcp.addr
        #print "To server:"
        #print tcp.server.data[:tcp.server.count] # WARNING - may be binary
        #print "To client:"
        #print tcp.client.data[:tcp.client.count] # WARNING - as above

def main():
    #nids_init()
    nids.param("san_num_hosts", 0)          # disable portscan detections
    nids.param("filename", sys.argv[1])
    nids.init()
    nids.register_tcp(tcp_callback)
    nids.run()

if __name__ == "__main__":
    main()