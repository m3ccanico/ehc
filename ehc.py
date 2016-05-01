#import nids
import dpkt
import sys
import re
import zlib
import StringIO
import getopt
import os
import hexdump

import TcpStream

def reassemble_chunked_body(chunked_body):
    body = ""
    stream = StringIO.StringIO(chunked_body)
    while True:
        line = stream.readline().strip()
        #print "\nline: %s<" % line
        #hexdump.hexdump(line)
        if not line: break                                          # stream returs an empty string in case of EOF
        length = int(line, 16)
        #print "length: %i" % length
        left = length+2                                             # read also the ending \r\n the drop them at the end to aling the next line
        chunk = ''
        while True:
            bit = stream.readline(left)
            left -= len(bit)
            chunk += bit
            if len(chunk) >= length or bit == "": break
            #print "   read %i, %i left" % (len(bit), left)

        chunk = chunk[0:-2]                                         # ignore last \r\n other \r\n are part of the stream
        #print "  chunk should read %i, read %i" % (length, len(chunk))
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
        name = "%s_%s-%s_%s-%02i.%s" % (src_ip, src_port, dst_ip, dst_port, i, ext)
        full_name = os.path.join(output_dir, name)
        sys.stdout.write(" exported %s as %s\n" % (content_type, name))
        o = open(full_name, 'wb')
        o.write(body)
        o.close
    else:
        sys.stdout.write(" ignored %s\n" % content_type)
    sys.stdout.flush()


def http_stream(request, response):
    #((src_ip, src_port), (dst_ip, dst_port)) = tcp.addr
    #print "stream %s:%s - %s:%s" % (src_ip, src_port, dst_ip, dst_port)
    
    # HTTP requests
    res = re.finditer(b"(GET|POST) ", request.data)
    lst = list(res)
    
    for i in range(len(lst)):
        start = lst[i].start()
        if i+1 < len(lst):
            end = lst[i+1].start()
        else:
            end = len(request.data)
        req = dpkt.http.Request(request.data[start:end])
        print " request:  0x%08x - 0x%08x: " % (start, end), req.method, req.headers.get('host', ''), req.uri

    # HTTP responses
    #print "responses 0x%08x - 0x%08x (0x%i)" % (0, tcp.client.count, tcp.client.count)
    res = re.finditer(b"HTTP/1.[01] \d", response.data) # convert to byte object
    lst = list(res)

    for i in range(len(lst)):
        start = lst[i].start()
        if i+1 < len(lst):
            end = lst[i+1].start()
        else:
            end = len(response.data)
        #http_response(tcp, tcp.client.data[start:end], i)
        #print " parsing 0x%08x - 0x%08x (%i): " % (start, end, end-start)
        try:
            rsp = None
            rsp = dpkt.http.Response(response.data[start:])
        except:
            print sys.exc_info()[0]
            #hexdump.hexdump(tcp.client.data[start:end])
            hexdump.hexdump(tcp.client.data)
            #exit()
        print " response: 0x%08x - 0x%08x: " % (start, end), rsp.status, rsp.headers.get('content-type', ''), rsp.headers.get('content-length', '')

    

#def http_stream(tcp):
#
#    requests = []
#    responses = []
#
#    read = 0
#    #print "server data:", tcp.server.count
#    while read < tcp.server.count:
#        req = dpkt.http.Request(tcp.server.data[read:])
#        requests.append(req)
#        print " request: ", req.method, req.uri, len(req)
#        read += len(req)
#
#    read = 0
#    #print "client data:", tcp.client.count
#    while read < tcp.client.count:
#        try:
#            rsp = dpkt.http.Response(tcp.client.data[read:])
#            responses.append(rsp)
#        except:
#            ((src_ip, src_port), (dst_ip, dst_port)) = tcp.addr
#            print " ERROR: Cannot parse response in (ip.addr==%s and tcp.port==%s and ip.addr==%s and tcp.port==%s)" % (src_ip, src_port, dst_ip, dst_port)
#            break
#        print " response: ", rsp.status, len(rsp)
#        #print rsp.headers
#        try:
#            length = int(rsp.headers['content-length']) #+ len(rsp.pack_hdr())
#        except KeyError:
#            length = len(rsp)
#        print " content length: ", length
#        read += len(rsp)
#        #read += length
#
#    print "read %i requests, %i responses" % (len(requests), len(responses))
#    #exit()

#def http_stream(tcp):
#    print "---"
#
#    p = HttpParser()
#    p.execute(tcp.server.data, len(tcp.server.data))
#    #print p.get_headers()
#    print p.get_method()
#    print p.get_url()
#    print p.get_status_code()
#
#    print "-"
#
#    p = HttpParser()
#    p.execute(tcp.client.data, len(tcp.client.data))
#    #print p.get_headers()
#    print p.get_method()
#    print p.get_url()
#    print p.get_status_code()


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
    
    output_dir = os.path.dirname(os.path.realpath(__file__))
    debug = False
    filename = ""
        
    #global output_dir, filename, debugging
    #
    try:
        opts, args = getopt.getopt(argv,"hdo:",["odir="])
    except getopt.GetoptError:
        print 'ehc.py -o <output directory> <filename>'
        sys.exit(2)
    
    for opt, arg in opts:
        if opt == '-h':
            print 'ehc.py -o <output directory>'
            sys.exit()
        if opt == '-d':
            debug = True
        elif opt in ("-o", "--odir"):
            output_dir = arg
    
    filename = argv[-1]
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # parse all TCP streams
    parser = TcpStream.TcpStreamParser(debug=debug)
    streams = parser.parse_pcap_file(filename)
    
    # find HTTP streams
    http_responses = []
    for tupl, stream in streams.iteritems():
        #print stream.data[:6]
        if stream.data[:6] == "HTTP/1":
            http_responses.append(tupl)
            #print tupl
            
    # find requests and create http_pairs
    http_pairs = []
    for response in http_responses:
        # tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)
        request = (response[1], response[0], response[3], response[2])
        if request in streams:
            #print "have request and reply"
            http_pairs.append((request, response))
        else:
            print "missing reply", request
    
    # parse http_pairs
    print "found %i HTTP http_pairs" % len(http_pairs)
    for pair in http_pairs:
        print pair[0]
        http_stream(streams[pair[0]], streams[pair[1]])

if __name__ == "__main__":
    main(sys.argv[1:])
