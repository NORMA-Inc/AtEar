__author__ = 'root'
import csv
import os
import string

def oui_search(mac_addr):
    mac_addr = string.upper(mac_addr)
    path = os.path.abspath('./databases/oui_database.csv')
    csv_file = open(path, 'rb')
    reader = csv.reader(csv_file)
    for row in reader:
        if mac_addr[0:8] == row[0]:
            return row[1]
    return 'Unknown'


def product_search(mac_addr):
    # mac_addr = string.upper(mac_addr)
    # path = os.path.abspath('./databases/product_database.csv')
    # csv_file = open(path, 'rb')
    # reader = csv.reader(csv_file)
    # for row in reader:
    #    if mac_addr[0:8] == row[0][0:8]:
    #        return row[1]
    return 'Unknown'
