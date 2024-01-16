import argparse
from pprint import pprint
from scapy.layers.http import *
from scapy.layers.inet import TCP, IP, ICMP
from scapy.all import *
from ttp import ttp
from graphviz import Digraph


http_reponse_template = """
{{ Http_Version | re('HTTP/\d.\d') }} {{ Status_Code }} {{ Reason_Phrase | ORPHRASE }}
content-type: {{ Content_Type | ORPHRASE }}
Location: {{ Location }}
content-length: {{ Content_Length }}

{{ data | _line_ }}
"""

http_request_template = """
{{ Method }} {{ Path }} {{ Http_Version | re('HTTP/\d.\d') }}
User-Agent: {{User_Agent | ORPHRASE }}
Accept: {{ Accept | ORPHRASE }}
Content-Type: {{ Content_Type | ORPHRASE }}
Content-Length: {{ Content_Length }}
Host: {{ Host }}

{{ data | _line_ }}
"""

redis_template = """
{{ type | re('.') }}{{ length | DIGIT }}
{{ data | _line_ }}
"""

mysql_query_template = """
{{ CMD }} {{ cols | re('[\w+,\s*]*') }}FROM {{ db }} {{ condition | ORPHRASE }}
"""

mysql_first_word_template = """
{{ CMD | WORD }}{{ data | re('.*') }}
"""

mysql_multiline_template = """
{{ re('\s+') }}{{ CMD | WORD }}{{ data | _line_ }}
"""

redis_ports = [6379, 6380, 6381, 6382]

mysql_cmd = {
    14: "PING",
    3: "QUERY",
    0: "OK",
}

parser = argparse.ArgumentParser(
                    prog='Sequence Diagram Generator',
                    description='PCAP in Diagram out')
parser.add_argument('filename')
args = parser.parse_args()

if args.filename:
    file = args.filename
else:
    parser.print_help()
    exit()

packets = sniff(offline=file, session=TCPSession)

flows = []
for packet in packets:
    label = ""
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            # Manage Plain HTTP Traffic
            if packet.haslayer(HTTP):
                if packet.haslayer(HTTPRequest):
                    label = f"{packet.sprintf('%HTTPRequest.Method%')[1:-1]} {packet.sprintf('%HTTPRequest.Path%')[1:-1]}"
                elif packet.haslayer(HTTPResponse):
                    label = f"{packet.sprintf('%HTTPResponse.Status_Code%')[1:-1]} {packet.sprintf('%HTTPResponse.Reason_Phrase%')[1:-1]}"
                else:
                    label = ""

            # Manage ElasticSearch HTTP
            if packet['TCP'].dport == 9200 or packet['TCP'].sport == 9200:
                if packet.haslayer('Raw'):
                    payload = packet['Raw'].load.decode('utf-8', errors='ignore')
                    
                    # Assume Elastic Search Response 
                    if packet['TCP'].sport == 9200:
                        parser = ttp(data=payload, template=http_reponse_template)
                        parser.parse(one=True)
                        results = parser.result(format='raw')[0][0]
                        if 'Status_Code' in results:
                            label = results['Status_Code']
                            if 'Reason_Phrase' in results:
                                label = f"{label} {results['Reason_Phrase']}"
                    else:
                        # Assume Elastic Search Request
                        # Not Rebuilding Frags
                        parser = ttp(data=payload, template=http_request_template)
                        parser.parse(one=True)
                        results = parser.result(format='raw')[0][0]
                        if 'Method' in results:
                            label = results['Method']
                            if 'Path' in results:
                                label = f"{label} {results['Path']}"
            
            # Manage Redis RESP
            if packet['TCP'].dport in redis_ports or packet['TCP'].sport in redis_ports:
                if packet.haslayer('Raw'):
                    payload = packet['Raw'].load.decode('utf-8', errors='ignore')
                    # Manage Simple Strings and Simple Errors
                    if payload[0] == "+" or payload[0] == "-":
                        label = payload[1:]
                    
                    parser = ttp(data=payload, template=redis_template)
                    parser.parse(one=True)
                    results = parser.result(format='raw')[0][0]
                    if len(results) >= 1:
                        if isinstance(results, list):
                            if 'type' in results[0]:
                                if results[0]['type'] == "*":
                                    label = results[1]['data']
                                    if label == "GET":
                                        label = f"{label} {results[2]['data']}"
                        elif isinstance(results, dict):
                            if 'type' in results:
                                if results['type'] == "$":
                                    label = "DATA"
                                elif results['type'] == ":":
                                    label = results['length']
                        else:
                            print(results)
            
            # Manage MySQL
            if packet['TCP'].sport == 3306 or packet['TCP'].dport == 3306:
                if packet.haslayer('Raw'):
                    payload = packet['Raw'].load
                    pl_size = int(payload[0:3][::-1].hex(), 16)
                    pl_pktnb = payload[3]
                    
                    if pl_pktnb == 0:
                        pl_cmd = mysql_cmd[payload[4]]
                        if pl_cmd == "QUERY":
                            parser = ttp(data=payload[5:pl_size + 5].decode('utf-8'), template=mysql_query_template)
                            parser.parse(one=True)
                            results = parser.result(format='raw')[0][0]
                            if 'CMD' in results:
                                label = results['CMD']
                                if 'db' in results:
                                    label = f"{label} {results['db']}"
                            else:
                                parser = ttp(data=payload[5:pl_size + 5].decode('utf-8'), template=mysql_first_word_template)
                                parser.parse(one=True)
                                results = parser.result(format='raw')[0][0]
                                if 'CMD' in results:
                                    label = results['CMD']
                                    if 'db' in results:
                                        label = f"{label} {results['db']}"
                                else:
                                    parser = ttp(data=payload[5:pl_size + 5].decode('utf-8'), template=mysql_multiline_template)
                                    parser.parse(one=True)
                                    results = parser.result(format='raw')[0][0][0]
                                    if 'CMD' in results:
                                        label = results['CMD']
                                        if 'db' in results:
                                            label = f"{label} {results['db']}"
                        else:
                            label = pl_cmd
                    else:
                        label = "RESPONSE"

            if label:
                flows.append([packet[IP].src, packet[IP].dst, label])

        elif packet.haslayer(ICMP):
            icmp_type_codes = {
                0: {
                    0: "echo-reply"
                },
                8: {
                    0: "echo-request"
                }
            }

            label = icmp_type_codes[packet['ICMP'].type][packet['ICMP'].code]
            flows.append([packet[IP].src, packet[IP].dst, label])


flow_host_count = []

for flow in flows:
    if flow[0] not in flow_host_count:
        flow_host_count.append(flow[0])
    if flow[1] not in flow_host_count:
        flow_host_count.append(flow[1])

pprint(flow_host_count)

hosts = {
    "Redis": ['10.10.70.1', '10.10.70.4', '10.10.70.5'],
    "Sync": ['10.10.101.3'],
    "SQL": ['10.10.70.2'],
    "ES": ['192.168.10.102'],
    "DAP": ['10.10.101.252']
}

for flow in flows:
    for host in hosts:
        if flow[0] in hosts[host]:
            flow[0] = host
        if flow[1] in hosts[host]:
            flow[1] = host

pprint(flows)

graph = Digraph(format='png')
graph.node_attr.update(color='lightblue2', style='filled')
graph.attr('node', shape='box', fontname="Arial", style='filled', fillcolor='#e2e2f0', rank="same")

for host in flow_host_count:
    graph.node(f'{host}_start', label=host)
    graph.edge(f'{host}_start', f'{host}_0', style='dashed', arrowhead='none')
    for i in range(len(flows)):
        graph.node(f'{host}_{i}', label='', shape='point', height='0')
        graph.edge(f'{host}_{i}', f'{host}_{i+1}', style='dashed', arrowhead='none')
    graph.node(f'{host}_end', label=host)
    graph.node(f'{host}_{i+1}', label='', shape='point', height='0')
    graph.edge(f'{host}_{i+1}', f'{host}_end', style='dashed', arrowhead='none')


current_connexion = 0
for flow in flows:
    connection = Digraph()
    connection.attr(rank='same')
    connection.edge(f'{flow[0]}_{current_connexion}', f'{flow[1]}_{current_connexion}', weight='0', arrowhead='vee', fontname='Arial', label=flow[2])
    graph.subgraph(connection)
    current_connexion += 1

graph.render(f'output_{file}', format='png', cleanup=False)
