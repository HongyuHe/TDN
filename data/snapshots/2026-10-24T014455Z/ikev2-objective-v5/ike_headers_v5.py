#!/usr/bin/env python3
"""Persist only IPv4, UDP, IKE and EF header fields from a finite exchange."""
from datetime import datetime,timezone
import json
import socket
import struct
def initial_payloads(data):
    results=[];kind=data[16];pos=28
    while kind and pos+4<=len(data):
        nxt,flags,length=struct.unpack('!BBH',data[pos:pos+4])
        if length<4 or pos+length>len(data):raise ValueError('Invalid generic payload length')
        body=data[pos+4:pos+length];item={'type':kind,'next_type':nxt,'length':length}
        if kind==33:
            proposals=[];q=0
            while q<len(body):
                if q+8>len(body):raise ValueError('Truncated proposal header')
                following,reserved,size,number,protocol,spi_len,count=struct.unpack('!BBHBBBB',body[q:q+8])
                if size<8+spi_len or q+size>len(body):raise ValueError('Invalid proposal size')
                transforms=[];t=q+8+spi_len
                while t<q+size:
                    if t+8>q+size:raise ValueError('Truncated transform')
                    next_t,reserved_t,tlen,ttype,reserved2,identifier=struct.unpack('!BBHBBH',body[t:t+8])
                    if tlen<8 or t+tlen>q+size:raise ValueError('Invalid transform size')
                    attributes=[];a=t+8
                    while a<t+tlen:
                        if a+4>t+tlen:raise ValueError('Truncated transform attribute')
                        typ,value=struct.unpack('!HH',body[a:a+4])
                        if typ&32768:attributes.append({'type':typ&32767,'format':'TV','value':value});a+=4
                        else:
                            if a+4+value>t+tlen:raise ValueError('Invalid TLV attribute length')
                            attributes.append({'type':typ,'format':'TLV','value_hex':body[a+4:a+4+value].hex()});a+=4+value
                    transforms.append({'next':next_t,'type':ttype,'id':identifier,'attributes':attributes});t+=tlen
                if len(transforms)!=count:raise ValueError('Transform count mismatch')
                proposals.append({'number':number,'protocol_id':protocol,'spi_size':spi_len,'transform_count':count,'transforms':transforms})
                q+=size
            item['proposals']=proposals
        elif kind==34:
            if len(body)<4:raise ValueError('Truncated KE group')
            item['key_exchange_group']=struct.unpack('!H',body[:2])[0]
            item['key_exchange_value_bytes_omitted']=len(body)-4
        results.append(item);pos+=length;kind=nxt
    if kind:raise ValueError('Truncated payload chain')
    return results
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(("eth0",0))
while True:
    frame,source=s.recvfrom(65535)
    if len(frame)<42 or frame[12:14]!=b"\x08\x00":continue
    ip=frame[14:];ihl=(ip[0]&15)*4
    if len(ip)<ihl+8 or ip[9]!=17:continue
    offset=struct.unpack("!H",ip[6:8])[0];udp=ip[ihl:];sport,dport,length=struct.unpack("!HHH",udp[:6])
    if sport not in [500,4500] and dport not in [500,4500]:continue
    r={"timestamp":datetime.now(timezone.utc).isoformat(),"interface":"eth0","packet_type":source[2],"source":socket.inet_ntoa(ip[12:16]),"destination":socket.inet_ntoa(ip[16:20]),"ip_total_length":struct.unpack("!H",ip[2:4])[0],"ip_header_length":ihl,"ip_id":struct.unpack("!H",ip[4:6])[0],"dont_fragment":bool(offset&0x4000),"more_fragments":bool(offset&0x2000),"fragment_offset_bytes":(offset&8191)*8,"udp_source":sport,"udp_destination":dport,"udp_length":length}
    data=udp[8:]
    if sport==4500 or dport==4500:
        if data[:4]!=b"\x00\x00\x00\x00":continue
        data=data[4:]
    if len(data)>=28:
        r.update({"ike_initiator_spi":data[:8].hex(),"ike_responder_spi":data[8:16].hex(),"ike_next_payload":data[16],"ike_version":data[17],"ike_exchange_type":data[18],"ike_flags":data[19],"ike_message_id":struct.unpack("!I",data[20:24])[0],"ike_length":struct.unpack("!I",data[24:28])[0]})
        if data[16]==53 and len(data)>=36:r.update({"ef_fragment_number":struct.unpack("!H",data[32:34])[0],"ef_total_fragments":struct.unpack("!H",data[34:36])[0],"ef_payload_length":struct.unpack("!H",data[30:32])[0]})
    if len(data)>=28 and data[18]==34:
        try:r['initial_payloads']=initial_payloads(data)
        except ValueError as error:r['initial_parse_error']=str(error)
    print(json.dumps(r),flush=True)
