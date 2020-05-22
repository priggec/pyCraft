#!/usr/bin/env python

from __future__ import print_function

import getpass
import sys
import re
import json
import threading
import time
from optparse import OptionParser

from minecraft import authentication
from minecraft.exceptions import YggdrasilError
from minecraft.networking.connection import Connection
from minecraft.networking.packets import Packet, clientbound, serverbound
from minecraft.compat import input


def get_options():
    parser = OptionParser()

    parser.add_option("-u", "--username", dest="username", default=None,
                      help="username to log in with")

    parser.add_option("-p", "--password", dest="password", default=None,
                      help="password to log in with")

    parser.add_option("-s", "--server", dest="server", default=None,
                      help="server host or host:port "
                           "(enclose IPv6 addresses in square brackets)")

    parser.add_option("-o", "--offline", dest="offline", action="store_true",
                      help="connect to a server in offline mode "
                           "(no password required)")

    parser.add_option("-d", "--dump-packets", dest="dump_packets",
                      action="store_true",
                      help="print sent and received packets to standard error")

    (options, args) = parser.parse_args()

    if not options.username:
        options.username = input("Enter your username: ")

    if not options.password and not options.offline:
        options.password = getpass.getpass("Enter your password (leave "
                                           "blank for offline mode): ")
        options.offline = options.offline or (options.password == "")

    if not options.server:
        options.server = input("Enter server host or host:port "
                               "(enclose IPv6 addresses in square brackets): ")
    # Try to split out port and address
    match = re.match(r"((?P<host>[^\[\]:]+)|\[(?P<addr>[^\[\]]+)\])"
                     r"(:(?P<port>\d+))?$", options.server)
    if match is None:
        raise ValueError("Invalid server address: '%s'." % options.server)
    options.address = match.group("host") or match.group("addr")
    options.port = int(match.group("port") or 25565)

    return options


def main():
    options = get_options()

    if options.offline:
        print("Connecting in offline mode...")
        connection = Connection(
            options.address, options.port, username=options.username)
    else:
        auth_token = authentication.AuthenticationToken()
        try:
            auth_token.authenticate(options.username, options.password)
        except YggdrasilError as e:
            print(e)
            sys.exit()
        print("Logged in as %s..." % auth_token.username)
        connection = Connection(
            options.address, options.port, auth_token=auth_token)

    if options.dump_packets:
        def print_incoming(packet):
            if type(packet) is Packet:
                # This is a direct instance of the base Packet type, meaning
                # that it is a packet of unknown type, so we do not print it.
                return
            print('--> %s' % packet, file=sys.stderr)

        def print_outgoing(packet):
            print('<-- %s' % packet, file=sys.stderr)

        connection.register_packet_listener(
            print_incoming, Packet, early=True)
        connection.register_packet_listener(
            print_outgoing, Packet, outgoing=True)

    def handle_join_game(join_game_packet):
        print('Connected.')

    connection.register_packet_listener(
        handle_join_game, clientbound.play.JoinGamePacket)

    # debug chat callback
    def print_chat(chat_packet):
        print("Message (%s): %s" % (
            chat_packet.field_string('position'), chat_packet.json_data))

    # lists serves as output message queues
    outQueue = []

    # boolean to tell if we are running
    running = True

    # console input callback
    def input_thread():
        while running:
            text = input()
            outQueue.append(text)
            time.sleep(0.1)

    # helper function to insert into message queue
    def insert_into_queue(message, player, globalFlag):
        if globalFlag:
            outQueue.append(message)
        else:
            outQueue.append('/msg ' + player + ' ' + message)
            

    # helper function to handle commands
    def process_message(message, player, playerId, globalFlag):
        
        if message == '$whoami':
            insert_into_queue('You are ' + player + '!', player, globalFlag)
                
        if message == '$selling':
            try:
                dealFile = open('deals.json', 'r')
                deals = json.loads(dealFile.read())
                dealFile.close()
                items = []
                for item in deals['selling']:
                    items.append(item['item'])
                insert_into_queue('Selling these items: ' + str(items), player, globalFlag)
            except:
                insert_into_queue('Sorry! Deals are not available at this time.', player, globalFlag)
                
        if message == '$buying':
            try:
                dealFile = open('deals.json', 'r')
                deals = json.loads(dealFile.read())
                dealFile.close()
                insert_into_queue('Buying these items: ' + str(deals['buying']), player, globalFlag)
            except:
                insert_into_queue('Sorry! Deals are not available at this time.', player, globalFlag)
                    
        if message == '$reps':
            try:
                dealFile = open('deals.json', 'r')
                deals = json.loads(dealFile.read())
                dealFile.close()
                outQueue.append('Representatives of Astara: ' + str(deals['representatives']))
            except:
                insert_into_queue('Sorry! Database is not available at this time.', player, globalFlag)
                    
        if message == '$help':
                insert_into_queue('Hi! I\'m the Astaran Trade Bot. Minimum trade value is 1db.' + \
                                  ' Here are some commands you can use: $selling, $buying, $price <item>, ' + \
                                  '$whoami, $reps, $help', player, globalFlag)
            
        if message.startswith('$price '):
            try:
                query = message[7:]
                dealFile = open('deals.json', 'r')
                deals = json.loads(dealFile.read())
                dealFile.close()
                name = ''
                price = ''
                for item in deals['selling']:
                    for alias in item['alias']:
                        if query.lower() == alias.lower():
                            name = item['item']
                            price = item['price']
                            break;
                    if name != '':
                        break;
                if name == '' or price == '':
                    insert_into_queue('Sorry! No price listed for that item.', player, globalFlag)
                else:
                    insert_into_queue('Astara sells ' + name + ' for ' + price, player, globalFlag)
            except:
                insert_into_queue('Sorry! No price listed for that item.', player, globalFlag)


    # chat processing callback
    def process_chat(chat_packet):
        position = chat_packet.field_string('position')
        if position == 'CHAT' or position == 'SYSTEM':
            data = json.loads(chat_packet.json_data)
                
            # Global Chat
            if data['translate'] == 'chat.type.text':
                # grab useful data from json
                message = data['with'][1]
                player = data['with'][0]['insertion']
                hoverStr = data['with'][0]['hoverEvent']['value']['text']
                start = hoverStr.index('id:\"') + 4
                end = hoverStr.index('\",type:')
                playerId = hoverStr[start:end]
                # print chat message
                outStr = playerId + ' (' + player + '): ' + message
                print(outStr)
                # log message
                log = open('log.txt', 'a')
                log.write(outStr + '\n')
                log.close()
                # process message
                process_message(message, player, playerId, True)
                
            # Private Chat
            if data['translate'] == 'commands.message.display.incoming':
                # grab useful data from json
                message = data['with'][1]['text']
                player = data['with'][0]['insertion']
                hoverStr = data['with'][0]['hoverEvent']['value']['text']
                start = hoverStr.index('id:\"') + 4
                end = hoverStr.index('\",type:')
                playerId = hoverStr[start:end]
                # print chat message
                outStr = playerId + ' (' + player + ') PRIVATE: ' + message
                print(outStr)
                # log message
                log = open('log.txt', 'a')
                log.write(outStr + '\n')
                log.close()
                # process message
                process_message(message, player, playerId, False)
                

    connection.register_packet_listener(
        print_chat, clientbound.play.ChatMessagePacket)

    # Register our chatbot logic
    connection.register_packet_listener(
        process_chat, clientbound.play.ChatMessagePacket)

    # start network thread
    connection.connect()

    # start console thread
    inThread = threading.Thread(target=input_thread)
    inThread.start()

    # Main bot console loop
    while running:
        try:
            time.sleep(0.05)
            if len(outQueue) != 0:
                msg = outQueue.pop()
                if msg == '/respawn':
                    print('Respawning...')
                    packet = serverbound.play.ClientStatusPacket()
                    packet.action_id = serverbound.play.ClientStatusPacket.RESPAWN
                    connection.write_packet(packet)
                elif msg == '/exit':
                    print('Disconnecting')
                    running = False
                else:
                    print('Sent Message: ' + msg)
                    packet = serverbound.play.ChatPacket()
                    packet.message = msg
                    connection.write_packet(packet)
        except KeyboardInterrupt:
            outQueue.append('/exit')


if __name__ == "__main__":
    main()
