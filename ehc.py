import nids
import sys
import re
import zlib

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

def http_response(tcp, data):
    #print data[:20]
    ((src_ip, src_port), (dst_ip, dst_port)) = tcp.addr
    try:
        (headers, body) = re.split(b"\r\n\r\n", data)
    except ValueError:
        #((src_ip, src_port), (dst_ip, dst_port)) = tcp.addr
        print "ERROR: Cannot split (ip.addr==%s and tcp.port==%s and ip.addr==%s and tcp.port==%s)" % (src_ip, src_port, dst_ip, dst_port)
        print str(data[:500])
        print ValueError
        print "<<<"
        return

    # read all headers, store relevant info
    content_type = ""
    content_length = 0
    content_encoding = ""

    for line in headers.splitlines():
        # skip header
        if re.match("HTTP/1.1", line):
            continue

        (name, value) = re.split(": ", line, 1)
        if name == "Content-Length":
            content_length = value
        if name == "Content-Type":
            content_type = value
        if name == "Content-Encoding":
            content_encoding = value

    # unpack compressed content
    if content_encoding == "gzip":
        try:
            body = zlib.decompress(body, zlib.MAX_WBITS|32)
        except:
            print "ERROR: Cannot decompress (ip.addr==%s and tcp.port==%s and ip.addr==%s and tcp.port==%s)" % (src_ip, src_port, dst_ip, dst_port)
            print headers
            print "<<<"
            return

    #if content_type == "":
    #    print "ERROR: No content type (ip.addr==%s and tcp.port==%s and ip.addr==%s and tcp.port==%s)" % (src_ip, src_port, dst_ip, dst_port)
    #    print headers
    #    print "<<<"

    # chose file extension based on content type
    ext = ""
    if re.search("javascript", content_type):
        ext = "js"
    elif re.search("html", content_type):
        ext = "html"
    elif re.search("shockwave-flash", content_type):
        ext = "swf"

    # ignore unknonw content
    if ext != "":
        name = "%s_%s-%s_%s.%s" % (src_ip, src_port, dst_ip, dst_port, ext)
        print "write file: %s" % name
        #o = open(name, 'wb')
        #o.write(body)
        #o.close
    else:
        print "ignored: %s" % content_type



def http_stream(tcp):
    res = re.finditer(b"HTTP/1.1 2", tcp.client.data)
    lst = list(res)

    for i in range(len(lst)):
        start = lst[i].start()
        if i+1 < len(lst):
            end = lst[i+1].start()
        else:
            end = len(tcp.client.data)
        http_response(tcp, tcp.client.data[start:end])

def tcp_callback(tcp):
    if tcp.nids_state == nids.NIDS_JUST_EST:
        ((src_ip, src_port), (dst_ip, dst_port)) = tcp.addr
        # ignore non HTTP ports
        if dst_port in (80, 8000, 8080):
            tcp.client.collect = 1
            tcp.server.collect = 1
    elif tcp.nids_state == nids.NIDS_DATA:
        # keep all of the stream's new data
        tcp.discard(0)
    elif tcp.nids_state in end_states:
        http_stream(tcp)

def main():
    nids.param("san_num_hosts", 0)          # disable portscan detections
    nids.param("filename", sys.argv[1])     # read from PCAP
    nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming
    nids.init()
    nids.register_tcp(tcp_callback)
    nids.run()

if __name__ == "__main__":
    main()
