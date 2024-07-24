ssh -o KexAlgorithms=diffie-hellman-group14-sha256 \
    -o HostKeyAlgorithms=rsa-sha2-512 \
    -o Ciphers=aes256-ctr \
    -o MACs=hmac-sha2-256 \
    -o Compression=no \
    ihainan@la.ihainan.me