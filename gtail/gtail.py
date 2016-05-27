#!/usr/bin/env python
#
# Graylog Tail, an application for tailing Graylog logs
# Brandon Vargo
import getpass
from collections import namedtuple
import ConfigParser
import argparse
import datetime
import os

import re
import requests
import sys
import time
import urllib
from json import dumps

MAX_DELAY = 10
DEFAULT_RANGE="5m"
DEFAULT_CONFIG_PATHS = [".gtail", os.path.expanduser("~/.gtail")]

# converts human readable time interval into seconds
def convert_time_interval(value):
    if not value:
        return None
    value = value.lower()
    value_int = 0
    if "w" in value:
        value_parts = value.split("w", 1)
        value_int += int(value_parts[0]) * 3600 * 24 * 7
        value = value_parts[1]
    if "d" in value:
        value_parts = value.split("d", 1)
        value_int += int(value_parts[0]) * 3600 * 24
        value = value_parts[1]
    if "h" in value:
        value_parts = value.split("h", 1)
        value_int+=int(value_parts[0])*3600
        value=value_parts[1]
    if "m" in value:
        value_parts = value.split("m", 1)
        value_int += int(value_parts[0]) * 60
        value = value_parts[1]
    value_parts = value.split("s", 1)
    if value_parts[0] == "":
        value_parts[0] = "0"
    value_int += int(value_parts[0])
    return value_int

# returns a bold version of text using ansi characters
def bold(text):
   make_bold = "\033[1m"
   reset = "\033[0;0m"
   return make_bold + str(text) + reset


# Generates new Graylog token
def generate_token(server_config):
    sys.stdout.write("Username: ")
    username = sys.stdin.readline().rstrip("\n")
    password = getpass.getpass()

    auth = (username, password)

    headers = {"accept": "application/json"}
    url = "{host}/users/{username}/tokens".format(host=server_config.uri, username=username)
    r = requests.get(url, auth=auth, headers=headers)
    if r.status_code != 200:
        raise Exception("Could not get tokens: {0}".format(r.status_code))

    resp = r.json()
    token_id = None
    if "tokens" in resp:
        for token in resp["tokens"]:
            if token["name"] == "gtail":
                token_id = token["token"]
                print "Token already exists"
                break

    if not token_id:
        url += "/gtail"
        r = requests.post(url)
        if r.status_code != 200:
            raise Exception("Could not generate a token: {0}".format(r.status_code))
        print "Generated new token"
        resp = r.json()
        token_id = resp["token"]

    if token_id:
        for path in DEFAULT_CONFIG_PATHS:
            if os.path.exists(path):
                f = open(path, "r")
                text = f.read()
                f.close()

                text = re.sub("(token:)(\s*)([a-zA-Z0-9]*)", "\\1 " + token_id, text)
                f = open(path, "w")
                f.write(text)
                f.close()
                print "Token saved in " + path
                break


# fetches the URL from the server
def fetch(server_config, url):
    if server_config.token:
        auth = (server_config.token, "token")
    else:
        auth = None

    headers = {"accept": "application/json"}
    r = requests.get(url, auth=auth, headers=headers)
    return r

def count(server_config, url):
    if server_config.token:
        auth = (server_config.token, "token")
    else:
        auth = None

    headers = {"accept": "application/json"}
    url = url.split("&limit=")[0]+"&limit=1"
    r = requests.get(url, auth=auth, headers=headers)
    if r.status_code !=200:
        raise Exception("Could not get message count from server. " \
                        "Status code: %d" % r.status_code)

    jsn = r.json()
    return jsn["total_results"]

# gets a list of active streams
def fetch_streams(server_config):
    r = fetch(server_config, server_config.uri + "/streams")
    streams = r.json()["streams"]
    # only active streams
    streams = filter(lambda s: s["disabled"] == False, streams)

    d = dict()
    for s in streams:
        d[s["id"]] = s

    return d

# lists streams in a pretty format
def list_streams(streams):
    streams = sorted(streams.values(), key=lambda s: s["title"].lower())
    for stream in streams:
        if stream["description"]:
            print bold(stream["title"]), "-", stream["description"]
        else:
            print bold(stream["title"])

# gets messages for the given stream (None = all streams) since the last
# message ID (None = start from some recent date)
def fetch_messages(server_config,
        query = None,
        stream_ids = None,
        last_message_id = None,
        fields = None,
        delay = MAX_DELAY,
        initial_range = None,
        initial_limit = None,
        from_date = None,
        to_date = None):
    url = []
    url.append(server_config.uri)

    if not from_date:
        if last_message_id:
            range = max(delay * 5, 300)
        else:
            range = initial_range
        url.append("/search/universal/relative?range={range}".format(range=range))
    else:
        url.append("/search/universal/absolute?from={from_date}&to={to_date}".format(from_date=from_date, to_date=to_date))

    # query terms
    if query:
        url.append("&query=" + urllib.quote_plus(query))
    else:
        url.append("&query=*")

    # fields list
    if fields:
        if "_id" not in fields:
            fields.append("_id")
        url.append("&fields=" + "%2C".join(fields))

    # stream ID
    if stream_ids:
        quoted = map(urllib.quote_plus, stream_ids)
        prefixed = map(lambda s: "streams:" + s, quoted)
        s = "%20OR%20".join(prefixed)
        url.append("&filter=" + s)

    # fetch
    url = ''.join(url)

    if last_message_id:
        limit = 1000
    else:
        if initial_limit:
            limit = initial_limit
        else:
            total = count(server_config, url)
            limit=total
    url += "&limit={0}".format(limit)

    r = fetch(server_config, url)
    if r.status_code != 200:
        raise Exception("Could not fetch messages from server. " \
                "Status code: %d" % r.status_code)

    # extact each message
    messages = map(lambda m: m["message"], r.json()["messages"])

    # convert the timestamp
    for m in messages:
        m["timestamp"] = datetime.datetime.strptime(m["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")

    # sort by date
    messages = sorted(messages, key=lambda m: m["timestamp"])

    # exclude any messages that we've seen before
    index = None
    for i, m in enumerate(messages):
        if m["_id"] == last_message_id:
            index = i
            break
    if index is not None:
        messages = list(messages)[index + 1:]

    return messages

# pretty prints a message
# streams, if provided, is the full list of streams; it is used for pretty
# printing of the stream name
def print_message(message, streams=None, fields=None, format="json"):
    s = dict()
    text = None
    if fields:
        count = 0
        for field in fields:
            if field != "_id" and field in message:
                count += 1
                s[field] = str(message[field])
    else:
        if "timestamp" in message:
            s["timestamp"] = str(message["timestamp"])
        if streams and "streams" in message:
            stream_ids = message["streams"]
            stream_names = []
            for sid in stream_ids:
                stream_names.append(streams[sid]["title"])
            s["streams"] = "[" + ", ".join(stream_names) + "]"
        if "facility" in message:
            s["facility"] = message["facility"]
        if "level" in message:
            s["level"] = message["level"]
        if "source" in message:
            s["source"] = message["source"]
        if "loggerName" in message:
            s["loggerName"] = message["loggerName"]

        if "full_message" in message:
            text = message["full_message"]
        elif "message" in message:
            text = message["message"]

    if format == "text":
        out = map(str, s.values())
    else:
        out = dumps(s)
    print bold(out)

    if text:
        print text

# config object and config parsing
Config = namedtuple("Config", "server_config")
ServerConfig = namedtuple("ServerConfig", "uri token")
def parse_config(config_paths):
    config = ConfigParser.RawConfigParser()
    read_paths = config.read(config_paths)
    if not read_paths:
        raise IOError("Could not read configuration file: %s" %
                ", ".join(config_paths))

    try:
        uri = config.get("server", "uri")
    except:
        raise Exception("Could not read server uri from configuration file.")

    try:
        token = config.get("server", "token")
    except:
        token = None

    return Config(ServerConfig(uri, token))

# finds all stream IDs that should be parsed
# if a stream name cannot be found, then an Exception is raised
def find_stream_ids(stream_names, streams):
    ids = []

    for stream_name in stream_names:
        ids.append(find_stream_id(stream_name, streams))

    return ids

# returns the stream ID
# if the ID cannot be found, then an exception is raised
def find_stream_id(stream_name, streams):
    # all stream names
    streams_lowercase = set()
    for stream in streams.values():
        stream_lowercase = stream["title"].lower()
        streams_lowercase.add(stream["title"].lower())

    # try to find the stream
    stream_ids = []
    for stream in streams.values():
        s = stream["title"].lower()
        if s.startswith(stream_name):
            stream_ids.append(stream["id"])

    # if more than one id, reset, and require exact name match
    if len(stream_ids) > 1:
        stream_ids = []
        for stream in streams.values():
            s = stream["title"]
            if s == stream_name:
                stream_ids.append(stream["id"])

    # if the stream was not found, error + list streams
    if not stream_ids:
        raise Exception("Stream '%s' could not be found " \
            "or is not active" % (stream_name))

    return stream_ids[0]


def check_date(value):
    datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    return value


def main():
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="Tail logs from Graylog.",
            epilog = """
Example configuration file:

[server]
; Graylog REST API
uri: http://graylog.example.com:12900
; optional username and password
username: USERNAME
password: PASSWORD

This file should be located at any of the following paths: %s.
""" % ", ".join(DEFAULT_CONFIG_PATHS))
    parser.add_argument("--stream", dest="stream_names",
            nargs="+",
            help="The name of the streams to tail. Default: all streams.")
    parser.add_argument("--list-streams", dest="list_streams",
            action="store_true",
            help="List streams and exit.")
    parser.add_argument("--query", dest="query",
            nargs="+",
            help="Query terms to search on")
    parser.add_argument("--fields", dest="fields",
                        nargs="+",
                        help="Fields to display")
    parser.add_argument("--format", dest="format",
                        choices=["text", "json"], default="json",
                        help="Display format")
    parser.add_argument("--delay", dest="delay",
                        type=int, default=MAX_DELAY,
                        help="Delay between Rest API calls (seconds)")
    parser.add_argument("--range", dest="range",
                        type=str,
                        help="Time range for initial fetch")
    parser.add_argument("--limit", dest="limit",
                        type=int, default=None,
                        help="Limit for initial fetch")
    parser.add_argument("--from", dest="from_date",
                        type=check_date,
                        help="From date/time with format yyyy-MM-dd HH:mm:ss")
    parser.add_argument("--to", dest="to_date",
                        type=check_date,
                        help="To date/timewith format yyyy-MM-dd HH:mm:ss")
    parser.add_argument("-f", dest="tail", action='store_true', default=False,
                        help="Follow the log")
    parser.add_argument("--generate-token", dest="token", action='store_true', default=False,
                        help="Generate new Graylog token")
    parser.add_argument("--config", dest="config_paths",
            nargs="+",
            help="Config files. Default: " + ", ".join(DEFAULT_CONFIG_PATHS))
    args = parser.parse_args()

    #
    # config file
    #

    config_paths = DEFAULT_CONFIG_PATHS
    if args.config_paths:
        config_paths = args.config_paths

    try:
        config = parse_config(config_paths)
    except Exception as e:
        print e
        return 1
    server_config = config.server_config


    if args.token:
        generate_token(server_config)
        os._exit(0)

    if args.range and (args.from_date or args.to_date):
        print "error: argument --range is not allowed if --from and --to are used"
        os._exit(1)

    if not args.from_date and not args.range:
        args.range = DEFAULT_RANGE

    #
    # find the stream
    #

    streams = fetch_streams(server_config)

    # list streams if needed
    if args.list_streams:
        list_streams(streams)
        return 0

    # parse stream name
    stream_ids = None
    if args.stream_names:
        try:
            stream_ids = find_stream_ids(args.stream_names, streams)
        except Exception as e:
            print e
            print
            list_streams(streams)
            return 1

    #
    # print log messages
    #

    try:
        last_message_id = None
        while True:
            # time-forward messages
            query = None
            fields = None
            if args.query:
                query = ' '.join(args.query)
            if args.fields:
                fields = []
                for field in args.fields:
                  fields.extend(field.split(","))
            try:
                messages = fetch_messages(
                        server_config = server_config,
                        query = query,
                        stream_ids = stream_ids,
                        last_message_id = last_message_id,
                        fields=fields,
                        delay=args.delay,
                        initial_range=convert_time_interval(args.range),
                        initial_limit=args.limit,
                        from_date=args.from_date,
                        to_date=args.to_date)

            except Exception as e:
                print e
                time.sleep(args.delay)
                continue

            # print new messages
            last_timestamp = None
            for m in messages:
                print_message(m, streams, fields=fields, format=args.format)
                last_message_id = m["_id"]
                last_timestamp = m["timestamp"]

            if args.from_date or not args.tail:
                break

            if last_timestamp:
                seconds_since_last_message = max(0, (datetime.datetime.utcnow() - last_timestamp).total_seconds())
                delay = min(seconds_since_last_message, args.delay)
                if delay > 2:
                    time.sleep(delay)
            else:
                time.sleep(args.delay)
    except KeyboardInterrupt:
        os._exit(0)

if __name__ == "__main__":
    rc = main()
    if rc:
        sys.exit(rc)
