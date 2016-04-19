import nids
import sys
import re
import zlib
import StringIO
import getopt
import os
import hexdump


end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)
output_dir = ''
filename = ''
debugging = False


def reassemble_chunked_body(chunked_body):
    body = ""
    stream = StringIO.StringIO(chunked_body)
    while True:
        line = stream.readline().strip()
        #print "\nline: %s" % line
        if not line: break;                     # stream returs empty string in case of EOF
        length = int(line, 16)
        #print "length: %i" % length
        chunk = stream.read(length)
        #print "should read %i, read %i" % (length, len(chunk))
        #print format(ord(chunk[0]), '02x')
        #print format(ord(chunk[1]), '02x')
        body += chunk
    return body


def http_response(tcp, data, i):
    #print data[:20]
    sys.stdout.write(" %02i:" % i)
    ((src_ip, src_port), (dst_ip, dst_port)) = tcp.addr
    try:
        (headers, body) = re.split(b"\r\n\r\n", data, 1)
    except ValueError:
        print " ERROR: Cannot split (ip.addr==%s and tcp.port==%s and ip.addr==%s and tcp.port==%s)" % (src_ip, src_port, dst_ip, dst_port)
        if debugging: hexdump.hexdump(str)
        return
    
    # read all headers, store relevant info
    content_type = ""
    content_length = 0
    content_encoding = ""
    transfer_encoding = ""
    
    for line in headers.splitlines():
        # skip header
        if re.match("HTTP/1.1", line):
            continue
        
        (name, value) = re.split(": ", line, 1)
        if name == "Content-Length":
            content_length = value
        elif name == "Content-Type":
            content_type = value
        elif name == "Content-Encoding":
            content_encoding = value
        elif name == "Transfer-Encoding":
            transfer_encoding = value;
    
    # reasemble body
    if transfer_encoding == "chunked":
        #print "chunked"
        sys.stdout.write('c')
        body = reassemble_chunked_body(body)
    
    # unpack compressed content
    if content_encoding == "gzip":
        sys.stdout.write('z')
        try:
            body = zlib.decompress(body, zlib.MAX_WBITS|32)
            #print "decompressed (ip.addr==%s and tcp.port==%s and ip.addr==%s and tcp.port==%s)" % (src_ip, src_port, dst_ip, dst_port)
        except:
            print " ERROR: Cannot decompress (ip.addr==%s and tcp.port==%s and ip.addr==%s and tcp.port==%s)" % (src_ip, src_port, dst_ip, dst_port)
            if debugging: hexdump.hexdump(body)
            return
    
    #if content_type == "":
    #    print " ERROR: No content type (ip.addr==%s and tcp.port==%s and ip.addr==%s and tcp.port==%s)" % (src_ip, src_port, dst_ip, dst_port)
    #    print headers
    
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
        full_name = os.path.join(output_dir, name)
        sys.stdout.write(" exported %s as %s\n" % (content_type, name))
        o = open(full_name, 'wb')
        o.write(body)
        o.close
    else:
        sys.stdout.write(" ignored %s\n" % content_type)
    sys.stdout.flush()


def http_stream(tcp):
    ((src_ip, src_port), (dst_ip, dst_port)) = tcp.addr
    print "stream %s:%s - %s:%s" % (src_ip, src_port, dst_ip, dst_port)
    res = re.finditer(b"HTTP/1.1 2", tcp.client.data)
    lst = list(res)

    for i in range(len(lst)):
        start = lst[i].start()
        if i+1 < len(lst):
            end = lst[i+1].start()
        else:
            end = len(tcp.client.data)
        http_response(tcp, tcp.client.data[start:end], i)


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


def main(argv):
    global output_dir, filename, debugging

    try:
        opts, args = getopt.getopt(argv,"hdo:",["odir="])
    except getopt.GetoptError:
        print 'ehc.py -o <output directory>'
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print 'ehc.py -o <output directory>'
            sys.exit()
        if opt == '-d':
            debugging = True
        elif opt in ("-o", "--odir"):
            output_dir = arg

    filename = argv[-1]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    nids.param("san_num_hosts", 0)          # disable portscan detections
    nids.param("filename", filename)     # read from PCAP
    nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming
    nids.init()
    nids.register_tcp(tcp_callback)
    nids.run()


if __name__ == "__main__":
    main(sys.argv[1:])
