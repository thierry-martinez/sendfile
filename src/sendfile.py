#!/usr/bin/env python3

"""sendfile implementation
Thierry.Martinez@inria.fr, 2020"""

import enum
import http.server
import os
import pathlib
import re
import socket
import sys
import typing
import urllib.parse
import yaml

import genshi.template
import requests
import shortuuid

BUFFER_SIZE = 0x1000
CONSTANT_OVERHEAD = 60

def read_yaml_file(filename):
    with open(filename, "r") as yaml_file:
        return yaml.load(yaml_file, Loader=yaml.FullLoader)

def get_prepare_filename(uuid):
    return "prepare/" + uuid

def get_socket_filename(uuid):
    return "socket/" + uuid

def get_infos_filename(uuid):
    return "infos/" + uuid

def get_url(base_url, uuid):
    return f"{base_url}/{uuid}/"

def check_legal_uuid(uuid):
    try:
        shortuuid.decode(uuid)
    except ValueError:
        raise circuits.web.exceptions.BadRequest()

def generate_index(
        uuid: str,
        secret: str,
        url: str,
        message: typing.Optional[str] = None,
) -> str:
    """generate HTML page from template"""
    template_dir = os.path.dirname(__file__)
    template_loader = genshi.template.loader.TemplateLoader(template_dir)
    template = template_loader.load("sendfile.html")
    title = "Send file"
    if message is None:
        message_str = ""
    else:
        title = message + " - " + title
        message_template = template_loader.load("message.html")
        message_str = message_template.generate(message=message)
    generated = template.generate(
        title=title,
        message=message_str,
        uuid=uuid,
        secret=secret,
        url=url,
    )
    return generated.render()

def index(base_url, message: typing.Optional[str] = None) -> str:
    uuid = shortuuid.uuid()
    secret = shortuuid.uuid()
    url = get_url(base_url, uuid)
    with open(get_prepare_filename(uuid), "w") as file:
        file.write(secret)
    return generate_index(uuid, secret, url, message)

def parse_options_header(header):
    try:
        semicolon = header.index(";")
        content_type = header[0:semicolon]
    except ValueError:
        content_type = header
        semicolon = len(header)
    content_type = content_type.lower().strip()
    options = {}
    while 1:
        try:
            equal = header.index("=", semicolon + 1)
        except ValueError:
            break
        option = header[semicolon + 1:equal].lower().strip()
        position = equal + 1
        while header[position:position + 1] == " ":
            position += 1
        if header[position:position + 1] == "\"":
            value = ""
            position += 1
            try:
                while header[position] != "\"":
                    if header[position] == "\\":
                        value += header[position + 1]
                        position += 2
                    else:
                        value += header[position]
                        position += 1
                position += 1
                while header[position:position + 1] == " ":
                    position += 1
                if position == len(header):
                    semicolon = len(header)
                elif header[position] == ";":
                    semicolon = position
                else:
                    break
            except IndexError:
                break
        else:
            try:
                semicolon = header.index(";", position)
                value = header[position:semicolon]
            except ValueError:
                value = header[position:]
                semicolon = len(header)
        options[option] = value
    return content_type, options

def parse_header(header):
    colon = header.index(":")
    key = header[0:colon].lower().strip()
    value = header[colon + 1:].strip()
    return key, value

class Failure(Exception):
    def __init__(self, message, error_code=500):
        super().__init__(message)
        self.error_code = error_code

class IterLines:
    def __init__(self, source):
        self.source = source

    def __iter__(self):
        while 1:
            line = b""
            while 1:
                data = self.source.peek()
                line_data = line + data
                try:
                    line_end = line_data.index(b"\r\n")
                    break
                except ValueError:
                    line = line_data
                    self.source.read(len(data))
            self.source.read(line_end - len(line) + 2)
            yield line_data[:line_end]

def next_non_blank(iter_lines):
    while 1:
        line = next(iter_lines)
        if line != b"":
            return line

class IterParts:
    def __init__(self, source, boundary):
        self.source = source
        self.boundary = boundary
        self.lines = IterLines(source)
        self.iter_lines = None
        self.separator = ("--" + boundary).encode("utf-8")
        self.terminated = False

    def __iter__(self):
        self.iter_lines = iter(self.lines)
        line = next_non_blank(self.iter_lines)
        if line != self.separator:
            raise Failure("Expected separator")
        while not self.terminated:
            headers = {}
            while 1:
                line = next(self.iter_lines)
                if line == b"":
                    break
                header = line.decode("utf-8")
                key, value = parse_header(header)
                headers[key.strip().lower()] = parse_options_header(value)
            value = IterValue(self)
            yield headers, value

class IterValue:
    def __init__(self, parts):
        self.parts = parts

    def __iter__(self):
        separated = False
        next_buf = b""
        separator = b"\r\n" + self.parts.separator
        while not separated:
            buf = next_buf
            data = buf + self.parts.source.peek()
            try:
                separator_pos = data.index(separator)
                separated = True
                data = data[:separator_pos]
                current_data = data
            except ValueError:
                if len(data) > len(separator):
                    next_buf = data[-len(separator):]
                    current_data = data[:-len(separator)]
                else:
                    next_buf = data
                    current_data = b""
            self.parts.source.read(len(data) - len(buf))
            yield current_data
        self.parts.source.read(len(separator))
        end_mark = self.parts.source.read(2)
        self.parts
        if end_mark == b"--":
            self.parts.terminated = True
        elif end_mark != b"\r\n":
            raise Failure("Expected end block")

class NotFound(Failure):
    def __init__(self):
        super().__init__("Not found", error_code=404)

class PositionStream:
    def __init__(self, stream):
        self.stream = stream
        self.position = 0

    def peek(self, *args):
        return self.stream.peek(*args)

    def read(self, *args):
        data = self.stream.read(*args)
        self.position += len(data)
        return data

def get_query_param(query, key):
    try:
        value, = query[key]
    except (ValueError, KeyError):
        value = None
    return value

def build_query(**args):
    query = ""
    for key, value in args.items():
        if query == "":
            query = "?"
        else:
            query += "&"
        query += urllib.parse.quote(key) + "=" + urllib.parse.quote(value)
    return query

class HTTPMethod:
    GET = 0
    POST = 1

def make_request_handler_class(config):
    base_path = config["base_path"]
    base_domain = config["base_domain"]
    base_url = base_domain + base_path
    redirect = config["redirect"]
    cas = config.get("cas", None)
    class RequestHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            """Respond to a GET request."""
            self.do_request(HTTPMethod.GET)

        def do_POST(self):
            """Respond to a POST request."""
            self.do_request(HTTPMethod.POST)

        def do_request(self, method):
            """Respond to a request."""
            parse = urllib.parse.urlparse(self.path)
            path = pathlib.PurePosixPath(parse.path)
            if "".join(path.parts[0:2]) == base_path:
                self.do_sendfile_request(method, parse, path.parts)
            else:
                self.send_redirect(redirect + self.path)

        def do_sendfile_request(self, method, parse, parts):
            """Respond to a request in /sendfile."""
            try:
                if len(parts) < 3:
                    query = urllib.parse.parse_qs(parse.query)
                    without_ticket = get_query_param(query, "without_ticket") == "yes"
                    if method == HTTPMethod.POST:
                        self.receive_form_post(without_ticket)
                    elif without_ticket:
                        self.send_success("OK!")
                    else:
                        self.show_form(parse, query)
                elif len(parts) < 5:
                    self.receive_file(parts[2])
                else:
                    raise NotFound()
            except Failure as exc:
                print(exc)
                self.send_response(exc.error_code)
                self.send_header("Content-type", "text/html; encoding=utf-8")
                self.end_headers()
                self.wfile.write("Invalid request".encode("utf-8"))

        def show_form(self, parse, query):
            ticket = get_query_param(query, "ticket")
            message = get_query_param(query, "message")
            if self.require_ticket(ticket, message):
                self.send_success(index(base_url, message))

        def send_success(self, string):
            self.send_response(200)
            self.send_header("Content-type", "text/html; encoding=utf-8")
            self.end_headers()
            self.wfile.write(string.encode("utf-8"))

        def require_ticket(self, ticket, message):
            if not cas:
                return True
            service = base_url
            if message:
                service += build_query(message=message)
            if ticket:
                r = requests.get(cas + "/serviceValidate" + build_query(ticket=ticket, service=service))
                if r.status_code == 200 and "<cas:authenticationSuccess>" in r.text:
                    return True
            self.send_redirect(cas + "/login" + build_query(service=service))

        def receive_form_post(self, without_ticket):
            content_type, options = parse_options_header(self.headers["Content-Type"])
            content_length = int(self.headers["Content-Length"])
            stream = PositionStream(self.rfile)
            boundary = options["boundary"]
            parts = IterParts(stream, boundary)
            params = {}
            for headers, iter_value in parts:
                content_disposition, options = headers["content-disposition"]
                name = options["name"]
                if name == "file":
                    filename = options["filename"]
                    uuid = params["uuid"]
                    secret = params["secret"]
                    estimated_size = (
                        content_length - stream.position -
                        len(get_url(base_url, uuid)) - 2 * len(boundary) -
                        CONSTANT_OVERHEAD)
                    self.send_file(
                        iter_value, filename, estimated_size, uuid, secret,
                        without_ticket)
                elif name in ["uuid", "secret"]:
                    value = b""
                    for content in iter_value:
                        value += content
                    params[name] = value.decode("utf-8")
                elif name == "url":
                    for content in iter_value:
                        pass
                else:
                    raise Failure("Unexpected option " + name)

        def send_file(self, iter_value, filename, size, uuid, secret, without_ticket):
            check_legal_uuid(uuid)
            prepare_filename = get_prepare_filename(uuid)
            with open(prepare_filename, "r") as prepare_file:
                real_secret = prepare_file.read()
            if secret != real_secret:
                raise Failure("Invalid secret")
            os.remove(prepare_filename)
            infos = { 'filename': filename, 'size': size }
            infos_filename = get_infos_filename(uuid)
            with open(infos_filename, "w") as infos_file:
                yaml.dump(infos, infos_file)
            try:
                socket_filename = get_socket_filename(uuid)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.bind(socket_filename)
                    try:
                        sock.listen(1)
                        connection, client_address = sock.accept()
                        try:
                            receive = connection.makefile("r")
                            client_address = receive.readline().strip()
                            target = connection.makefile("wb")
                            for data in iter_value:
                                target.write(data)
                        finally:
                            connection.close()
                    finally:
                        os.remove(socket_filename)
            finally:
                os.remove(infos_filename)
            message = f"File {filename} sent to {client_address}."
            args = {}
            if without_ticket:
                args["without_ticket"] = "yes"
            self.send_redirect(build_query(message=message, **args))

        def receive_file(self, uuid):
            check_legal_uuid(uuid)
            infos_filename = get_infos_filename(uuid)
            try:
                with open(infos_filename, "r") as infos_file:
                    infos = yaml.load(infos_file, Loader=yaml.FullLoader)
            except FileNotFoundError:
                raise NotFound()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                try:
                    sock.connect(get_socket_filename(uuid))
                except socket.error:
                    raise Failure("Socket error")
                sock.sendall((self.client_address[0] + "\n").encode('utf-8'))
                self.send_response(200)
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{infos['filename']}\"")
                self.send_header("Content-Length", infos["size"])
                self.end_headers()
                while 1:
                    data = sock.recv(BUFFER_SIZE)
                    if not data:
                        break
                    self.wfile.write(data)

        def send_redirect(self, location):
            self.send_response(303)
            self.send_header('Location', location)
            self.end_headers()

    return RequestHandler

def serve(config):
    port = int(config["port"])
    RequestHandlerClass = make_request_handler_class(config)
    server_object = http.server.ThreadingHTTPServer(
        server_address=('', port),
        RequestHandlerClass=RequestHandlerClass)
    server_object.serve_forever()

serve(read_yaml_file(sys.argv[1]))
