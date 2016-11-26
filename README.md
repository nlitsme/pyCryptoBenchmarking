results
=======

symmetric crypto
----------------

| pycrypt   | cryptography  |    factor |  algorithm
| ---------:| -------------:|  --------:|:-----
|  756499.3 |      379890.2 |      0.50 | AES
|  424332.1 |      259299.5 |      0.61 | 3DES.64
|  229043.5 |      259282.9 |      1.13 | 3DES.128
|  226057.2 |      255484.5 |      1.13 | 3DES.192
|  487464.4 |      302878.6 |      0.62 | Blowfish
|  351429.9 |      317410.7 |      0.90 | CAST5
|  797340.5 |      361095.3 |      0.45 | RC4

Most symmetric ciphers are significantly faster in `pyCrypto`.

hash algorithms
---------------

message size = 64 kbyte, in Mbyte/sec

| pycrypt   | cryptography  |    factor |  algorithm
| ---------:| -------------:|  --------:|:-----
|        57 |         343   |      5.98 | sha224
|        53 |         333   |      6.19 | sha256
|        83 |         487   |      5.85 | sha384
|        81 |         487   |      6.00 | sha512
|       910 |         781   |      0.86 | sha1
|       678 |         419   |      0.62 | md5
|        40 |         199   |      4.89 | ripemd160


message size = 32 bytes, in Mbyte/sec

| pycrypt   | cryptography  |    factor |  algorithm
| ---------:| -------------:|  --------:|:-----
|      16.2 |           2.8 |      0.17 | sha224
|      15.7 |           2.9 |      0.18 | sha256
|      13.0 |           2.8 |      0.21 | sha384
|      12.4 |           2.8 |      0.22 | sha512
|      15.3 |           2.8 |      0.19 | sha1
|      16.2 |           2.8 |      0.18 | md5
|      14.6 |           1.5 |      0.10 | ripemd160

Both `pycrypto` and `cryptography` have some call overhead.
for `pycrypto` the byterate stabalizes for messages over 1K,
while for `cryptography this happens for messages over 16K.

That said, `cryptography` is generally faster for very large messages,
while `pycrypto` is fast for smaller messages.
For the SHAxxx algorithms, the cross over point is around 1k mesage size.
for SHA1 and MD5 `pycrypto` is always faster.

asymmetric crypto
-----------------

| pow()     | pycrypt   | cryptography  |    factor |  algorithm
| ---------:| ---------:| -------------:|  --------:|:-----
|   17267.1 |   12137.1 |      33917.4  |      2.8  | rsa.1024
|    4920.6 |    4217.5 |      18242.9  |      4.3  | rsa.2048
|    1440.8 |    1467.3 |       6448.8  |      4.4  | rsa.4096

So the `cryptography` library is generally faster.
The `pycrypt` performance is roughly equal to using the `pow()` function.

random numbers
--------------

in Mbyte/sec

| random | sysrand | pycrypti  |   r/s |    s/p |  msgsize |
| ------:| -------:| ---------:| -----:| ------:| --------:|
|  478.0 |    55.9 |       2.0 |   8.6 |   27.4 |       32 |
|  726.4 |    70.9 |       3.1 |  10.2 |   22.6 |       64 |
| 1148.9 |    81.0 |       3.8 |  14.2 |   21.1 |      128 |
| 1476.4 |    88.1 |       4.4 |  16.8 |   20.1 |      256 |
| 1757.5 |    93.4 |       3.9 |  18.8 |   24.2 |      512 |
| 2141.6 |    94.3 |       2.6 |  22.7 |   36.6 |     1024 |
| 2339.3 |   100.2 |       1.9 |  23.3 |   53.4 |     2048 |
| 2405.1 |    94.8 |       1.1 |  25.4 |   83.1 |     4096 |
| 2361.0 |   101.9 |       0.6 |  23.2 |  158.7 |     8192 |
| 2568.1 |    97.7 |       0.3 |  26.3 |  286.8 |    16384 |


Conclusion: secure random numbers are expensive.
