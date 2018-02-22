import socket
import sys
import ssl
import time
from multiprocessing.pool import ThreadPool
import sys, os, base64, datetime, hashlib, hmac 
import requests # pip install requests
import select
from socket import error as socket_error


def create_request_string(region, function_name, request_parameters):

    # ************* TASK 1: CREATE THE REQUEST*************
    method = 'POST'
    service = 'lambda'
    host = 'lambda.us-west-2.amazonaws.com'.replace('us-west-2', region)
    endpoint = 'https://' + host
    path = '/2015-03-31/functions/my-hello-world/invocations'.replace('my-hello-world', function_name)
    request_url = endpoint + path

    # the content is JSON.
    content_type = 'application/x-amz-json-1.0'

    # Read AWS access key from env. variables or configuration file. Best practice is NOT
    # to embed credentials in code.
    #access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    #secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

    access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key is None or secret_key is None:
        print 'No access key is available.'
        sys.exit()

    # Create a date for headers and the credential string
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

    canonical_uri = path
    canonical_querystring = ''
    canonical_headers = 'content-type:' + content_type + '\n' \
                        + 'host:' + host + '\n'  \
                        + 'x-amz-date:' + amz_date + '\n'
    signed_headers = 'content-type;host;x-amz-date'


    # Create payload hash. In this example, the payload (body of
    # the request) contains the request parameters.
    payload_hash = hashlib.sha256(request_parameters).hexdigest()

    # Combine elements to create create canonical request
    canonical_request = method + '\n' \
                    + canonical_uri + '\n' \
                    + canonical_querystring + '\n' \
                    + canonical_headers + '\n' \
                    + signed_headers + '\n' \
                    + payload_hash


    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()


    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key using the function defined above.


    # Key derivation functions. See:
    # http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    def getSignatureKey(key, date_stamp, regionName, serviceName):
        kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
        kRegion = sign(kDate, regionName)
        kService = sign(kRegion, serviceName)
        kSigning = sign(kService, 'aws4_request')
        return kSigning


    signing_key = getSignatureKey(secret_key, date_stamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()


    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    # Put the signature information in a header named Authorization.
    authorization_header = algorithm + ' ' \
            + 'Credential=' + access_key + '/' \
            + credential_scope + ', ' \
            +  'SignedHeaders=' + signed_headers + ', ' \
            + 'Signature=' + signature

    headers = {'authorization':authorization_header,
               'content-type':content_type,
               'host':host,
               'x-amz-date':amz_date}


    # ************* TASK 5: CONVERT REQUEST TO STRING *************
    # Put the signature information in a header named Authorization.

    req = requests.Request('POST', request_url, data=request_parameters, headers=headers)
    prepped = req.prepare()

    request_str = ""
    request_str += method + " " + path + "?" + " " + "HTTP/1.1" + "\r\n"
    for header in sorted(prepped.headers.keys()):
        #print header
        request_str += header + ":" + prepped.headers[header] + "\r\n"
    request_str += "\r\n"
    request_str += request_parameters

    return request_str



def invoke_lambda(region, function_name, request_parameters, num_requests, num_threads):

    request_str = create_request_string(region, function_name, request_parameters)

    t1 = time.time()

    connections = []

    host = 'lambda.us-west-2.amazonaws.com'.replace('us-west-2', region)
    # def establish_connection(key):
    #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     s.setblocking(False)
    #     s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #     wrappedSocket = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)
    #     wrappedSocket.connect((host , 443))
    #     #print(wrappedSocket.gettimeout())
    #     connections.append(wrappedSocket)
    # pool = ThreadPool(num_threads)
    # pool.map(establish_connection, [None] * num_requests)
    # pool.close()
    # pool.join()

    import errno

    for i in range(num_requests):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        wrappedSocket = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)
        connections.append(wrappedSocket)

    next_waiting_connections = connections[:]
    while True:
        done = True
        waiting_connections = next_waiting_connections[:]
        next_waiting_connections = []
        for connection in waiting_connections:
            try:
                connection.connect((host , 443))
            except socket_error as serr:
                #print "socket err "
                #print serr
                if serr.errno != errno.EISCONN:
                    next_waiting_connections.append(connection)
                    done = False
            except ValueError:
                #print "value error"
                pass

        if not done:
            time.sleep(0.01)
        else:
            # all done
            break


        # ecode = wrappedSocket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        # print ("ecode is " + str(ecode))
        # while ecode == 61:
        #     print("ecode is 61, sleeping...")
        #     time.sleep(0.01)
        #     ecode = wrappedSocket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        # print errno.errorcode[ecode]
        #print(ready_to_read)
        #print(ready_to_write)
        #print(in_error)
        #print(wrappedSocket.gettimeout())

    # ready_to_write = []
    # chunks = [connections[x:x+100] for x in xrange(0, len(connections), 100)]
    # for chunk in chunks:
    #     while len(ready_to_write) != len(chunk):
    #         ready_to_read, ready_to_write, in_error = select.select([], chunk, [])
    #         time.sleep(0.01)

    t2 = time.time()

    def send_request(c):
        c.setblocking(True)
        c.sendall(request_str)

    pool = ThreadPool(num_threads)
    pool.map(send_request, connections)
    pool.close()
    pool.join()

 
    #for c in connections:
    #    # c.setblocking(True)
    #    c.sendall(request_str)

    t3 = time.time()

    # ready_to_read, ready_to_write, in_error = select.select(connections, [], [])

    for c in connections:
        c.setblocking(True)
        data = c.recv(4096)

    t4 = time.time()
    print('num connections: ' + str(num_requests) + " threads: " + str(num_threads))
    print('connection: ' + str(t2-t1))
    print('sent: ' + str(t3-t2))
    print('recv: ' + str(t4-t3))



def main():
    if (len(sys.argv) < 3):
        print("usage: ./invoker_socket_clean.py num_connections num_threads\n")
        exit(0)
    region = "us-west-2"
    function_name = "my-hello-world"
    data = '{"hello":"world"}'
    num_requests = int(sys.argv[1])
    num_threads = int(sys.argv[2])
    invoke_lambda(region, function_name, data, num_requests, num_threads)


if __name__ == "__main__":
    main()
