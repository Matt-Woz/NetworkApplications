#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time


def setupArgumentParser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='A collection of Network Applications developed for SCC.203.')
    parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
    subparsers = parser.add_subparsers(help='sub-command help')

    parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
    parser_p.set_defaults(timeout=6)
    parser_p.add_argument('hostname', type=str, help='host to ping towards')
    parser_p.add_argument('--count', '-c', nargs='?', type=int,
                          help='number of times to ping the host before stopping')
    parser_p.add_argument('--timeout', '-t', nargs='?',
                          type=int,
                          help='maximum timeout before considering request lost')
    parser_p.set_defaults(func=ICMPPing)

    parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                     help='run traceroute')
    parser_t.set_defaults(timeout=1, protocol='icmp')
    parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
    parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                          help='maximum timeout before considering request lost')
    parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                          help='protocol to send request with (UDP/ICMP)')
    parser_t.set_defaults(func=Traceroute)

    parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
    parser_w.set_defaults(port=8080)
    parser_w.add_argument('--port', '-p', type=int, nargs='?',
                          help='port number to start web server listening on')
    parser_w.set_defaults(func=WebServer)

    parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
    parser_x.set_defaults(port=8000)
    parser_x.add_argument('--port', '-p', type=int, nargs='?',
                          help='port number to start web server listening on')
    parser_x.set_defaults(func=Proxy)

    args = parser.parse_args()
    return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count + 1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (
                packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


# Author: Mateusz Wozakowski
class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        startTime = time.time()
        while (startTime + timeout - time.time()) > 0:
            # 2. Once received, record time of receipt, otherwise, handle a timeout
            try:
                recPacket, addr = icmpSocket.recvfrom(1024)
            except socket.timeout:
                raise Exception("Timeout - No response in given time")
            timeOfReceive = time.time()
            # 3. Compare the time of receipt to time of sending, producing the total network delay
            totalDelay = (timeOfReceive - self.timeOfSend) * 1000
            # 4. Unpack the packet header for useful information, including the ID
            ourHeader = recPacket[20:28]
            Type, code, checksum, p_id, sequence = struct.unpack("bbHHH", ourHeader)
            # 5. Check that the ID matches between the request and reply
            if p_id == ID:
                # 6. Return total network delay
                return totalDelay

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        ourChecksum = 0
        ourHeader = struct.pack("bbHHH", 8, 0, ourChecksum, ID, 1)
        # 2. Checksum ICMP packet using given function
        ourChecksum = super().checksum(ourHeader)
        # 3. Insert checksum into packet
        ourPacket = struct.pack("bbHHH", 8, 0, ourChecksum, ID, 1)
        # 4. Send packet using socket
        icmpSocket.sendto(ourPacket, (destinationAddress, 1))
        # 5. Record time of sending
        self.timeOfSend = time.time()

    def doOnePing(self, destinationAddress, timeout):
        packetID = os.getpid()
        # 1. Create ICMP socket
        ourSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
        ourSocket.settimeout(timeout)
        # 2. Call sendOnePing function
        self.sendOnePing(ourSocket, destinationAddress, packetID)
        # 3. Call receiveOnePing function
        networkDelay = self.receiveOnePing(ourSocket, destinationAddress, packetID, timeout)
        # 4. Close ICMP socket
        ourSocket.close()
        # 5. Return total network delay
        return networkDelay

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        ipAddress = socket.gethostbyname(args.hostname)
        # 2. Call doOnePing function, approximately every second
        while True:
            ping = self.doOnePing(ipAddress, 1)
            # 3. Print out the returned delay (and other relevant details) using the printOneResult method
            super().printOneResult(ipAddress, 0, ping, 55, args.hostname)
            time.sleep(1)
        # 4. Continue this process until stopped


class Traceroute(NetworkApplication):
    Destination = 2301  # Random int used when ICMP type 0 packet returned
    NoOfPackets = 0  # Used for calculating packet loss

    # This function waits to receive a packet back and splits it into its parts
    def receiveOnePing(self, icmpSocket, destinationAddress, timeout):
        # 1. Wait for the socket to receive a reply
        startTime = time.time()
        while (startTime + timeout - time.time()) > 0:
            # 2. Once received, record time of receipt, otherwise, handle a timeout
            try:
                recPacket, addr = icmpSocket.recvfrom(1024)  # Receive data from the socket
            except socket.timeout:
                icmpSocket.close()
                break  # Get out of loop if timeout error
            timeOfReceive = time.time()
            # 3. Compare the time of receipt to time of sending, producing the total network delay
            totalDelay = (timeOfReceive - self.timeOfSend) * 1000
            self.NoOfPackets = self.NoOfPackets + 1
            # 4. Unpack the packet header for useful information, including the ID
            ourHeader = recPacket[20:28]  # Extract header from the packet
            packetSize = sys.getsizeof(recPacket)
            Type, code, checksum, packetID, sequence = struct.unpack("bbHHH", ourHeader)
            # 5. Check that the ID matches between the request and reply
            if Type == 0:  # If destination packet returned
                return totalDelay, addr, self.Destination, packetSize
            elif Type == 11:  # Intermediate packet
                return totalDelay, addr, 0, packetSize
        return 0, 0, 0, 0

    # This function creates the header and sends it to the destination address
    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        ourChecksum = 0
        ourHeader = struct.pack("bbHHH", 8, 0, ourChecksum, ID, 1)
        # 2. Checksum ICMP packet using given function
        ourChecksum = super().checksum(ourHeader)
        # 3. Insert checksum into packet
        ourPacket = struct.pack("bbHHH", 8, 0, ourChecksum, ID, 1)
        # 4. Send packet using socket
        try:
            icmpSocket.sendto(ourPacket, (destinationAddress, 1))
        except socket.error as error:
            print("Error: %s", error)
            icmpSocket.close()
            return
        # 5. Record time of sending
        self.timeOfSend = time.time()

    # This function creates the socket and calls the relevant functions to do a ping
    def doOnePing(self, destinationAddress, timeout, ttl):
        packetID = os.getpid() & 0xFFFF
        # 1. Create ICMP socket
        ourSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
        ourSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        ourSocket.settimeout(timeout)
        # 2. Call sendOnePing function
        self.sendOnePing(ourSocket, destinationAddress, packetID)
        # 3. Call receiveOnePing function
        networkDelay = self.receiveOnePing(ourSocket, destinationAddress, timeout)
        # 4. Close ICMP socket
        ourSocket.close()
        # 5. Return total network delay
        return networkDelay  # Returns ping & other packet info

    # This function initalises and contains the main logic of traceroute
    def __init__(self, args):
        maxHops = 31
        # Please ensure you print each result using the printOneResult method!
        print('Traceroute to: %s...' % (args.hostname))
        ipAddress = socket.gethostbyname(args.hostname)
        for ttl in range(1, maxHops):  # Repeat for all nodes
            for i in range(1, 4):  # Repeat each measurement 3 times
                networkDelay, addr, info, size = self.doOnePing(ipAddress, args.timeout, ttl)
                try:
                    hostname = socket.gethostbyaddr(addr[0])
                except:
                    hostname = None
                try:
                    if hostname is None:
                        super().printOneResult(addr[0], size, networkDelay, ttl, "Unavailable hostname ")
                    else:
                        super().printOneResult(addr[0], size, networkDelay, ttl, hostname[0])
                except:
                    print("Timeout!")
            if info == 2301:  # If destination has been reached
                packetLoss = self.NoOfPackets / (ttl * i)  # Calculate packet loss
                packetLoss = packetLoss * 100
                packetLoss = 100 - packetLoss
                self.printAdditionalDetails(packetLoss)
                break


class WebServer(NetworkApplication):

    def handleRequest(tcpSocket, ourSocket):
        while True:
            connection, address = ourSocket.accept()
            request = connection.recv(1024).decode('utf-8')
            list = request.split(' ')
            method = list[0]
            reqFile = list[1]
            ourFile = reqFile.split('?')[0]
            ourFile = ourFile.lstrip('/')
            if (ourFile == ''):
                ourFile = 'index.html'

            try:
                file = open(ourFile, 'rb')
                response = file.read()
                file.close()
                header = 'HTTP/1.1 200 OK\n'
                header += 'Content type: ' + 'text/html' + '\n\n'
            except Exception as error:
                header = 'HTTP/1.1 404 Not Found \n\n'
                response = '<html><body><center><h3>Error 404: File not found</h3><p>Python HTTP Server</p></center></body></html>'.encode(
                    'utf-8')
            final_response = header.encode('utf-8')
            final_response += response
            connection.send(final_response)
            connection.close()

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        # 2. Bind the server socket to server address and server port
        # 3. Continuously listen for connections to server socket
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket
        Host = '127.0.0.1'
        Port = 8080
        ourSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ourSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ourSocket.bind((Host, Port))
        ourSocket.listen(1)
        self.handleRequest(ourSocket)


class Proxy(NetworkApplication):

    # This function takes the whole http requests and trims it to a useable url
    def cutRequest(self, request):
        url = request.split(' ')[1]  # isolates url from get request
        index = url.find('://')
        if index == -1:  # if :// in url is not found
            temp = url
        else:
            temp = url[(index + 3):]  # gets rid of :// in the url
        positionOfPort = temp.find(':')
        positionOfWebserver = temp.find('/')
        if positionOfWebserver == -1:
            positionOfWebserver = len(temp)
        if positionOfPort == -1:  # if url has no port
            port = 80  # set default
            webserver = temp[:positionOfWebserver]  # gets rid of final /
            return port, webserver
        port = int(
            (temp[(positionOfPort + 1):])[:positionOfWebserver - positionOfPort - 1])  # takes specified port in url
        webserver = temp[:positionOfPort]
        return port, webserver

    # This function accepts the connection from the host, to be used in creating the proxy
    def handleRequest(self, socket):
        while True:
            connection, address = socket.accept()  # connection = new socket object, address = address bound to new socket
            request = connection.recv(4096).decode('utf-8')  # request = GET <host> http/1.1
            port, webServer = self.cutRequest(request)  # cuts http request to its seperate parts
            self.createProxy(webServer, port, connection, request)

    # This function creates the proxy and waits for a response
    def createProxy(self, server, port, connection, request):
        hostName = socket.gethostbyname(server)
        proxySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Creates proxy socket and configures
        proxySocket.connect((socket.gethostbyname(server), port))
        proxySocket.send(request.encode('utf-8'))
        response = proxySocket.recv(4096)
        lenOfResponse = len(response)
        if lenOfResponse > 0:  # If there is a response
            connection.send(response)
        proxySocket.close()
        connection.close()

    # This function initialises the program - Creates & configures the socket and calls further functions
    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))
        ourHost = socket.gethostname()
        print(ourHost)
        ourPort = args.port
        ourSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ourSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ourSocket.bind((ourHost, ourPort))
        ourSocket.listen(1)
        self.handleRequest(ourSocket)


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
