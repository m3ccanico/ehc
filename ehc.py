#!/usr/bin/env python

import dpkt
import sys
import re
import getopt
import os
import hexdump
import logging
import socket

import TcpStream


def http_stream(request, response, req_tupl, rsp_tupl):    
    # HTTP requests
    requests = []
    res = re.finditer(b"(GET|POST) ", request.data)
    lst = list(res)
    
    for i in range(len(lst)):
        start = lst[i].start()
        if i+1 < len(lst):
            end = lst[i+1].start()
        else:
            end = len(request.data)
        req = dpkt.http.Request(request.data[start:end])
        requests.append(req)
        logging.debug("request:  0x%08x - 0x%08x: %s %s %s" % \
            (start, end, req.method, req.headers.get('host', ''), req.uri))

    # HTTP responses
    responses = []
    res = re.finditer(b"HTTP/1.[01] \d", response.data) # convert to byte object
    lst = list(res)

    for i in range(len(lst)):
        start = lst[i].start()
        if i+1 < len(lst):
            end = lst[i+1].start()
        else:
            end = len(response.data)

        try:
            rsp = dpkt.http.Response(response.data[start:])
            responses.append(rsp)
            logging.debug("response: 0x%08x - 0x%08x: %s %s %s" % \
                (start, end, rsp.status, rsp.headers.get('content-type', ''), rsp.headers.get('content-length', '')))
        except:
            requests.pop()  # remove request if response parsing failed
            logging.warning("response (%i): cannot parse HTTP response - #%i, range:0x%08x-0x%08x, tupl:%s:%i-%s:%i" % \
                (response.id, i, start, end, socket.inet_ntoa(rsp_tupl[0]), rsp_tupl[2], socket.inet_ntoa(rsp_tupl[1]), rsp_tupl[3]))
            #print sys.exc_info()[0]
            #hexdump.hexdump(response.data[start:end])

    return (requests, responses)


def main(argv):
    
    output_dir = os.path.dirname(os.path.realpath(__file__))
    debug = False
    filename = ""
    cnt = 0
    
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

    
    level = logging.INFO  # WARNING INFO
    if debug:
        level = logging.DEBUG

    logging.basicConfig(level=level,format="%(levelname)s: %(message)s")
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # parse all TCP streams
    parser = TcpStream.TcpStreamParser()
    streams = parser.parse_pcap_file(filename)
    
    # find HTTP streams
    http_responses = []
    for tupl, stream in streams.iteritems():
        if stream.data[:6] == "HTTP/1":
            http_responses.append(tupl)
            
    # find requests and create http_pairs
    http_pairs = []
    for response in http_responses:
        # tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)
        request = (response[1], response[0], response[3], response[2])
        if request in streams:
            http_pairs.append((request, response))
        else:
            logging.error("missing reply: %s" % request)
    
    map_file_name = os.path.join(output_dir, "http.map")
    map_file = open(map_file_name, 'w')

    # parse http_pairs
    for pair in http_pairs:
        (requests, responses) = http_stream(streams[pair[0]], streams[pair[1]], pair[0], pair[1])
        logging.info("found HTTP stream pair - req-strm:%i, resp-strm:%i, #req:%i, #resp:%i" % \
            (streams[pair[0]].id, streams[pair[1]].id, len(requests), len(responses)))

        if len(requests) != len(responses):
            logging.warning("unbalanced requests/responses - req-strm:%i, resp-strm:%i, %s:%i-%s:%i" % \
                (streams[pair[0]].id, streams[pair[1]].id, socket.inet_ntoa(pair[0][0]), pair[0][2], socket.inet_ntoa(pair[0][1]), pair[0][3]))
            #continue

        for i in range(min(len(requests),len(responses))):
            if requests[i] == None:
                logging.error("request does not exist - %s:%i-%s:%i" % \
                 (socket.inet_ntoa(pair[0][0]), pair[0][2], socket.inet_ntoa(pair[0][1]), pair[0][3]))
                continue
            if responses[i] == None:
                logging.error("response does not exist - %s:%i-%s:%i" % \
                 (socket.inet_ntoa(pair[1][0]), pair[1][2], socket.inet_ntoa(pair[1][1]), pair[1][3]))
                continue

            # chose file extension based on content type
            content_type = responses[i].headers.get('content-type', '')
            ext = ""
            if re.search("javascript", content_type):
                ext = "js"
            elif re.search("html", content_type):
                ext = "html"
            elif re.search("shockwave-flash", content_type):
                ext = "swf"
            
            # ignore unknonw content
            if ext != "":
                name = "%04i.%s" % (cnt, ext)
                cnt += 1
                full_name = os.path.join(output_dir, name)
                o = open(full_name, 'wb')
                o.write(responses[i].body)
                o.close()
                logging.info("exported %s as %s" % (content_type, name))
                map_file.write("%s\t%s\t%s\n" % (requests[i].headers.get('host', ''), requests[i].uri, name))
            else:
                logging.info("ignored - content_type %s, resp-strm:%i" % (content_type, streams[pair[1]].id))

    map_file.close()


if __name__ == "__main__":
    main(sys.argv[1:])

