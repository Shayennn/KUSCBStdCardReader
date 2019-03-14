#! /usr/bin/python3

import keyboard

import os
import sys
import time
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString
from smartcard.System import readers

from desfire.protocol import DESFire,DESFireCommunicationError
from desfire.pcsc import PCSCDevice

class KUSTDCardObserver(CardObserver):
    def update(self, observable, actions):

        (addedcards, removedcards) = actions

        for card in addedcards:
            if 'ACR122U' not in card.reader:
                print('Detected another reader added card.')
                continue
            print("+ Inserted:", toHexString(card.atr))

            if not card.atr:
                print("Did not correctly detected card insert")
                continue

            if card.atr != [0x3B ,0x81 ,0x80 ,0x01 ,0x80 ,0x80]:
                print("Accept Mifare DESFire EV1 only")
                observable.rmthread()
                continue

            connection = card.createConnection()
            connection.connect()
            card.connection = connection.component

            desfire = DESFire(PCSCDevice(connection.component))
            try:
                desfire.select_application(131201)
            except DESFireCommunicationError as err:
                print(err)
                continue
            except IndexError as err:
                print('Too Fast to remove card')
                continue

            try:
                data = desfire.read_data_file(12)
                std_id = bytes(data).decode('utf-8')[:10]
                print('DATA:',std_id)
                keyboard.write(std_id)
                keyboard.send('enter')
            except IndexError as err:
                print('Too Fast to remove card')
                continue
            except DESFireCommunicationError as err:
                print(err)
                continue

        for card in removedcards:
            if 'ACR122U' not in card.reader:
                print('Detected another reader removed card.')
                continue
            print("- Removed:", toHexString(card.atr))

def main():

    if 'linux' in sys.platform and os.getegid() != 0:
        sys.exit("You must to run this sctipt as root.")

    available_reader = readers()
    if not available_reader:
        sys.exit("No card readers detected")

    card_monitor = CardMonitor()
    card_observer = KUSTDCardObserver()
    card_monitor.addObserver(card_observer)

    while True:
        time.sleep(0.2)


if __name__ == "__main__":
    main()
