# PyDns
This is a manual implementation of DNS resolving in python. It works by packing the bytes required for a a request and parsing the response from the socket.

### Usage
```python main.py <valid domain>```

The results are printed as an array of strings. e.g.
```
python3 main.py www.google.com
['216.58.192.164']
```
