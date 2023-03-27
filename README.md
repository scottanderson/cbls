Install build dependencies
```
sudo apt-get install cmake libgmp-dev
```

Build the server
```
make
```

Build and start the server
```
make start
```

Testing
```
# Send a BNLS_NULL packet
echo -en '\x03\x00\x00' | nc localhost 9367

# Send a BNLS_AUTHORIZE packet
echo -en '\x0a\x00\x0enetcat\x00' | nc localhost 9367
```

Clean build
```
make clean
```
