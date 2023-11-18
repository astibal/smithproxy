# Webhook quick HOWTO

## Intro Information

Smithproxy, when configured, sends various information to webhook server.

This currently (upcoming version `0.9.32`) means mostly connection-related data 
and is planned to be further extended to other types of information.

Webhooks, unless explicitly noted, will **NOT** block your traffic. 

## Configuration

```
settings = 
{
  // ...
  webhook = 
  {
    enabled = true
    url = "http://localhost:5000/webhook/<SECRET_ID>"
    tls_verify = true
    hostid = "oneofmany1"
  }
}
```
Above config snippet is quite self-explanatory. When `enabled` is true,
webhook is considered as enable and will be used.

- `url` - webhook server URL. Indeed, you should use https.  
- `tls_verify` - if https and this value is true, standard system CA store is used to check HTTPS certificate. 
- `hostid` - if set, you can override using hostname as a json `source` value. 


##  Message format
Message format, as received into python `dict`.

Important elements:
- `type` - which kind of message it is
    - `proxy` - information about smithproxy events (other values are reserved for other/external daemons using webhook)
- `action` - proxy action name 
- `source` - hostname or `hostid` if configured, uniquely identifying smithproxy instance 
- `id` - proxy object unique ID, consisting of daemon start random and random OID

Unless explicitly noted, `smithproxy` is not expecting anything as a response.  
Unless explicitly noted, response is not processed and is completely ignored.

## Message samples

### Ping
> `smithproxy` -> `webhook`: proxy keepalive notification

```python
  {
   'action': 'ping', 
   'source': 'oneofmany1', 
   'type': 'proxy'
  }
```
This message is solely to inform webhook server that proxy is alive.
It's sent once in a while :).

### New neighbor IP

> `smithproxy` -> `webhook`: new communicating source IP detected

```python
  {
   'action': 'neighbor',
   'address': '172.30.1.10',
   'source': 'oneofmany1',
   'state': 'new',
   'type': 'proxy'
  }
```

### Connection Start/Stop

> `smithproxy` -> `webhook`: connection details 

```python
  # connection start 
  {
   'action': 'connection-start',
   'details': {'info': {'session': 'ssli_172.30.1.10:32954+ssli_1.2.3.4:443'}},
   'id': 'Proxy-A65E609B-OID-FEE9B1098109',
   'source': 'oneofmany1',
   'type': 'proxy'
  },
  # connection stop
  {
    'action': 'connection-stop',
    'details': {
        'info': {'bytes_down': 610,
              'bytes_up': 1367,
              'l7': {'app': 'http2',
                     'details': ['https://example.com/$/minVersion/v1/get',
                                 'https://example.com/$/minVersion/v1/get_smt_else']},
              'policy': 3,
              'session': 'ssli_172.30.1.10:32954+ssli_1.2.3.4:443',
              'tls': {'sni': 'example.com' }
               }
    },
    'id': 'Proxy-A65E609B-OID-FEE9B1098109',
    'source': 'oneofmany1',
    'type': 'proxy'
  }
```
This info message contains most useful information collected without special features used.
Besides of basic L4 data, it contains TLS and HTTP engine details, if those are present. 

### Connection Info

> `smithproxy` -> `webhook`: connection details collected by policy features

Json message as python `dict` if `statistics` feature is used on policy (and webhook is enabled):

```python
  {
    'action': 'connection-info', 
    'details': {
        'statistics': 
            {'entropy': 
                {
                'left': {'bytes_accounted': 610, 'entropy': 5.247643097125175, 'top_byte': 101, 'top_byte_frequency': 24, 'top_byte_ratio': 0.08955223880597014}, 
                'right': {'bytes_accounted': 1367, 'entropy': 5.328814149578886, 'top_byte': 101, 'top_byte_frequency': 42, 'top_byte_ratio': 0.08203125}
                }, 
             'flow': {'aggregate_rates': [{'aggBD': 785, 'aggBU': 268, 'aggRD': 1.0, 'aggRU': -1.1754385964912282, 'interval_index': 0}], 'skew': 0.49097815764482433, 'skew_all': 0.49097815764482433}, 
             # ...
            }
    }, 
    'id': 'Proxy-A65E609B-OID-FEE9B1098109', 
    'source': 'oneofmany1', 
    'type': 'proxy'
  }
```

This message is generated, if policy `feature` is used. After proxy is closed and destroyed,
policy feature data are collected and sent to webhook.  

Key `details` contains data from all policy features (you see only `statistics` in the example).   
That means that on the same level would be i.e. `access-request` data if feature was enabled.


> Note this message may arrive after `connection-stop`. Your webhook implementation should not rely on particular 
`connection-stop` vs. `connection-info` order.

### Access-Request policy feature

> `smithproxy` -> `webhook`: request incoming connection data exchange allowance

```python
  {
   'action': 'access-request',
   'details': {'policy': 3,
               'session': 'ssli_172.30.1.10:32954+ssli_1.2.3.4:443'},
   'id': 'Proxy-A65E609B-OID-FEE9B1098109',
   'source': 'oneofmany1',
   'type': 'proxy'
   }
```

This message is sent from proxy to webhook, waiting **SYNCHRONOUSLY** for response.   
This will **BLOCK** until proxy receives response or times out.  

Also note proxy connection is established, but has not yet transferred any data.

> `webhook` -> `smithproxy` : response to access-request (with 200 HTTP code)

Minimum valid response:
```python
  { 'access-response': 'accept' }
```
or

```python
   { 'access-response': 'reject' }
```
If `'reject'` value is received, proxy is destroyed and no data are ever transferred. 
Any other case allows the connection to start data exchange.

Response data received from webhook are stored, and later collected 
into `connection-info` webhook message.  
This could be useful to send from webhook some additional information for later use,
which smithproxy can't be aware of.



## Testing webhook server
Well, don't judge me, just giving you some starting point!

Install flask:  
`apt install python3-flask`  
or  
`pip3 install flask` (using `venv` recommended)

Code:
```python
from flask import Flask, request, jsonify
from pprint import pprint

app = Flask(__name__)

@app.route('/webhook/<string:key>', methods=['POST'])
def webhook(key: str):

    # some code to check `key` string secret

    # Process the incoming JSON payload
    payload = request.json

    # Replace the below line with your processing logic
    print(f"Received payload:")
    pprint(payload)

    try:
        if payload["action"] == "access-request":
            result = "accept"
            
            # sample reject IPv6
            if "2001:67c:68::76" in payload['details']['session']:
                result = "reject"

            return jsonify({
                "access-response": result
            }), 200
    except KeyError as e:
        print(f'KeyError: {e}')

    return jsonify({"status": "success"}), 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)

```