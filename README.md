# HMAC-Circom

This repository contains a implementation of HMAC-SHA256 in Circom.

## HMAC-SHA256 Overview

HMAC (Hash-based Message Authentication Code) is a specific type of message authentication code (MAC) involving a cryptographic hash function and a secret cryptographic key. It may be used to simultaneously verify both the data integrity and authenticity of a message.

For more detailed information, refer to:

- [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) (HMAC)
- [RFC 4231](https://datatracker.ietf.org/doc/html/rfc4231#section-4) (Test Cases)

## Circuit Implementation

The circuits in this repository implement HMAC-SHA256. The implementation strictly follows the HMAC standard as described in RFC 2104, using SHA-256 as the hash function. The circuit is designed to be generic and supports:

- Variable message length
- Key size of 256 bits (can be adapted for other sizes)

Check the [HmacSha256](https://github.com/crema-labs/hmac-circom/blob/main/circuits/hmac.circom)

### Constraints

## Test Results

| Test Vector | Constraints | Message Length (n) | Key Length (k) | Execution Time (s) |
| ----------- | :---------: | :----------------: | :------------: | :----------------: |
| 1           |   161,640   |         8          |       20       |       10.249       |
| 2           |   161,676   |         28         |       4        |       10.175       |
| 3           |   162,018   |         50         |       20       |       10.285       |
| 4           |   162,063   |         50         |       25       |       10.755       |
| 5           |   161,748   |         20         |       20       |       10.016       |
| 6           |   225,581   |         54         |      131       |       14.216       |
| 7           |   288,991   |        152         |      131       |       17.882       |

These tests were performed on a Mac Pro with M1 chip and 8GB RAM. The test vectors are based on RFC 4231, which provides standard test cases for HMAC-SHA256.

To run these tests, use the following command:

```bash
yarn test
```
