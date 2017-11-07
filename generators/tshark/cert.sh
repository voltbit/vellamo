tshark -r $1 -Y "ssl.handshake.certificate" -V | grep "Certificate:"
