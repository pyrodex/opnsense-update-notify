#!/usr/bin/env python3

import json
import sys

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import yaml
import yamale

# SMTP
import smtplib
from email.message import EmailMessage

# Logging
import logging
from pprint import pprint
from datetime import datetime
# Argument parsing
import argparse

parser = argparse.ArgumentParser(description="OPNsense firmware notification utility")
parser.add_argument("directory", help="Directory containing the yaml files used by the program")
args = parser.parse_args()

def valid_conf(schema_file, config_file):
    schema_yamale = yamale.make_schema(schema_file)
    config_yamale = yamale.make_data(config_file)

    try:
        yamale.validate(schema_yamale, config_yamale)
    except ValueError as e:
        for r in e.results:
            for err in r.errors:
                logging.error('%s', err)
        sys.exit(1)

def parse_res(resp):
    if int(resp['updates']) > 0:
        message = 'OPNsense Updates Available\n\n'
        message += f"Packages to download: {resp['updates']}\n"
        message += f"Download size: {resp['download_size']}\n\n"

        new_pkgs = resp['new_packages']

        if len(new_pkgs) > 0:
            message += 'New:\n\n'

            if type(new_pkgs) == dict:
                for pkg in new_pkgs:
                    message += f"{new_pkgs[pkg]['name']} {new_pkgs[pkg]['version']}\n"
            else:
                for pkg in new_pkgs:
                    message += f"{pkg['name']} {pkg['version']}\n"

        upg_pkgs = resp['upgrade_packages']

        if len(upg_pkgs) > 0:
            message += 'Upgrade:\n\n'

            if type(upg_pkgs) == dict:
                for pkg in upg_pkgs:
                    message += f"{new_pkgs[pkg]['name']} from {new_pkgs[pkg]['current_version']}" + \
                        f" to {new_pkgs[pkg]['new_version']}\n"
            else:
                for pkg in upg_pkgs:
                    message += f"{pkg['name']} from {pkg['current_version']}" + \
                        f" to {pkg['new_version']}\n"

        reinst_pkgs = resp['reinstall_packages']

        if len(reinst_pkgs) > 0:
            message += 'Reinstall:\n\n'

            if type(reinst_pkgs) == dict:
                for pkg in reinst_pkgs:
                    message += f"{new_pkgs[pkg]['name']} {new_pkgs[pkg]['version']}\n"
            else:
                for pkg in reinst_pkgs:
                    message += f"{pkg['name']} {pkg['version']}\n"

        if resp['upgrade_needs_reboot'] == '1':
            message += '\nThis requires a reboot\n'

    if resp['upgrade_major_version'] != '':
        try:
            message
        except NameError:
            message = 'OPNsense Major Upgrade Available\n'
        else:
            message += 'OPNsense Major Upgrade Available\n'
        message += f"{resp['upgrade_major_version']} from {resp['product_version']}"

    try:
        message
    except NameError:
        message = None

    return message

def send_telegram(msg, chatid, token):
    url = f'https://api.telegram.org/bot{token}/sendMessage?text={msg}&chat_id={chatid}'
    r = requests.get(url)
    return r

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

schema_filename = "/schema.yml"
config_filename = "/config.yml"
schema_file = args.directory + schema_filename
config_file = args.directory + config_filename
valid_conf(schema_file, config_file)
with open(config_file) as f:
    conf = yaml.safe_load(f)

# Logging
logging.basicConfig(filename=conf['logging']['logfile'], filemode='a',format='%(asctime)s: %(levelname)s - %(message)s',datefmt='%m/%d/%Y %H:%M:%S',level=logging.INFO)
logging.info('Script execution started')
logging.info('Reading configuration from %s',args.directory)

host       = conf['opnsense']['host']
# verify is false if self signed
verify     = not conf['opnsense']['self_signed']
api_key    = conf['opnsense']['api_key']
api_secret = conf['opnsense']['api_secret']

t_chatid = conf['telegram']['chatid']
t_token = conf['telegram']['token']

smtp_from = conf['email']['from']
smtp_to = conf['email']['to']
smtp_host = conf['email']['host']

url = 'https://' + host + '/api/core/firmware/status'

r = requests.get(url,verify=verify,auth=(api_key, api_secret))

if r.status_code == 200:
    res = json.loads(r.text)
    message = parse_res(res)
    if message != None:
        if conf['emitter'] == "email":
            msg = EmailMessage()
            msg.set_content(message)
            msg['Subject'] = f'OPNsense Updater Notification'
            msg['From'] = smtp_from
            msg['To'] = smtp_to
            s = smtplib.SMTP(smtp_host)
            s.send_message(msg)
            s.quit()
        elif conf['emitter'] == "telegram":
            send_telegram(message, t_chatid, t_token)
        else:
            logging.error('Unknown emitter %s!',conf['emitter'])
        
    else:
        logging.info('There are no updates or major upgrades available')

else:
    logging.error('Unknown status code %s', {res.text})

logging.info('Script execution finished')
