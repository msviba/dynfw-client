#!/usr/bin/env python3.11

import os
import re
import tempfile
import argparse
import urllib.request

import zmq
import zmq.auth
import msgpack

import subprocess
import logging
import signal
import sys
import time

# create logger
logger = logging.getLogger("logging_dynfw")
logger.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                              "%Y-%m-%d %H:%M:%S")


# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)

TMP_CERT_LOCATION = os.path.join(tempfile.gettempdir(), "dynfw_client_certificates")
DOWNLOADED_SERVER_KEY_PATH = os.path.join(tempfile.gettempdir(), "dynfw_client_certificates", "server.pub")

SN_MSG_REGEXP = "^([a-z0-9_]+/)*[a-z0-9_]+$"
SN_MSG = re.compile(SN_MSG_REGEXP)

run_true = True

def get_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", "-s",
                        metavar="URL",
                        required=False,
                        default="sentinel.turris.cz",
                        help="URL of Sentinel DynFW publisher"
                        )
    parser.add_argument("--port", "-p",
                        required=False,
                        default=7087,
                        type=int,
                        help="Port to connect to"
                        )
    cert_def = parser.add_mutually_exclusive_group()
    cert_def.add_argument("--cert-file", "-c",
                          metavar="PATH",
                          required=False,
                          help="Path to server's certificate"
                          )
    cert_def.add_argument("--download-cert", "-d",
                          metavar="URL",
                          required=False,
                          default="https://repo.turris.cz/sentinel/dynfw.pub",
                          help="URL of published certificate"
                          )

    return parser

def pfctl_table(command, data=[]):
    try:
        pfctl_out = subprocess.check_output(["/sbin/pfctl", "-t", "sentinel-bl", "-T", command] + data, text=True, stderr=subprocess.STDOUT)
        logger.info(pfctl_out.strip("\n\r")+" "+', '.join(data))
    except subprocess.CalledProcessError as e:
        logger.error(f"Error: {e}")
    except FileNotFoundError:
        logger.error("pfctl not found")


def process_message(msg_type, payload, sub):
    def pf_add(data, batch_len=10):
        for i in range(0, len(data), batch_len):
            pfctl_table("add", data[i:i + batch_len])
    

    if msg_type == "dynfw/delta":
        if payload["delta"] == "negative":
            pfctl_table("del", [payload["ip"]])
        elif payload["delta"] == "positive":
            pfctl_table("add", [payload["ip"]])


    elif msg_type == "dynfw/list":
        pfctl_table("flush")
        pf_add(payload["list"])
        logger.info("Loaded dynfw/list. Waiting for dynfw/delta ...")
        sub.setsockopt(zmq.UNSUBSCRIBE, b"dynfw/list")
        sub.setsockopt(zmq.SUBSCRIBE, b"dynfw/delta")



def main():
    args = get_arg_parser().parse_args()

    prepare_tmp_dir()

    if args.cert_file:
        server_key_file = args.cert_file
    else:
        download_certificate(args.download_cert)
        server_key_file = DOWNLOADED_SERVER_KEY_PATH

    ctx = zmq.Context.instance()
    sub = prepare_socket(ctx, args.server, args.port, server_key_file)

    signal.signal(signal.SIGINT, signal_handler)
    logger.info("DynFW client connected and running. Waiting for dynfw/list ...")
    while run_true:
        msg = sub.recv_multipart()
        msg_type, payload = parse_msg(msg)

        process_message(msg_type, payload, sub)



def prepare_tmp_dir():
    if not os.path.exists(TMP_CERT_LOCATION):
        os.mkdir(TMP_CERT_LOCATION, mode=0o700)


def download_certificate(url):
    response = urllib.request.urlopen(url)
    with open(DOWNLOADED_SERVER_KEY_PATH, "wb") as f:
        f.write(response.read())


def prepare_socket(ctx, addr, port, keyfile):
    sub = ctx.socket(zmq.SUB)
    sub.ipv6 = True

    client_public, client_secret = prepare_certificates()
    server_public = load_server_key(keyfile)

    sub.curve_secretkey = client_secret
    sub.curve_publickey = client_public
    sub.curve_serverkey = server_public
    sub.connect("tcp://{}:{}".format(addr, port))

    # I want to subscribe first list of BL IPs
    sub.setsockopt(zmq.SUBSCRIBE, b"dynfw/list")

    return sub


def prepare_certificates():
    key_path = os.path.join(TMP_CERT_LOCATION, "client.key_secret")
    if not os.path.exists(key_path):
        public, secret = zmq.auth.create_certificates(TMP_CERT_LOCATION, "client")
        assert public
        assert secret

    client_public, client_secret = zmq.auth.load_certificate(key_path)

    return client_public, client_secret


def load_server_key(keyfile):
    public, _ = zmq.auth.load_certificate(keyfile)

    return public


class InvalidMsgError(Exception):
    pass


def parse_msg(data):
    try:
        msg_type = str(data[0], encoding="UTF-8")
        if not SN_MSG.match(msg_type):
            raise InvalidMsgError("Bad message type definition")
        payload = msgpack.unpackb(data[1])

    except IndexError:
        raise InvalidMsgError("Not enough parts in message")

    except (TypeError, msgpack.exceptions.UnpackException, UnicodeDecodeError):
        raise InvalidMsgError("Broken message")

    return msg_type, payload


def signal_handler(sig, frame):
    print('Ending...')
    run_true = False
    time.sleep(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
