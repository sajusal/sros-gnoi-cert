# SR OS gNOI certificate management
This tutorial is on gRPC gNOI certificate management in SR OS.

gNOI is a gRPC service for performing operations on the router. For more details, please visit [gNOI Openconfig page](https://github.com/openconfig/gnoi/tree/main).

For more details on SR OS implementation of gRPC services, refer to [SR OS Documentation](https://documentation.nokia.com/sr/24-3/7x50-shared/system-management/grpc.html)

## SR OS Node

Use the [topology](sros.clab.yml) file to create a single SR OS node lab using [Containerlab](https://containerlab.dev/).

To deploy the lab:

```srl
sudo clab dep -t sros.clab.yml
```

## Client
We will be using [gnoic](https://gnoic.kmrd.dev/) as the client. Refer to the page for installation procedure.

Verify gnoic is installed on your client.

```
gnoic version
```

Expected output:

```
version : 0.1.0
 commit : a5e9584
   date : 2024-12-18T19:04:06Z
 gitURL : https://github.com/karimra/gnoic
   docs : https://gnoic.kmrd.dev
```

## SR OS Configuration

This tutorial is based on SR OS release `24.7R1`.

On the SR OS side, gRPC should be enabled along with gNOI Cert operation. On the user configuration, gRPC should be allowed and gNOI cert operations should also be permitted in the user profile.

To enter candidate mode, use `edit-config private`.

```
    /configure system grpc admin-state enable
    /configure system grpc allow-unsecure-connection
    /configure system grpc gnoi cert-mgmt admin-state enable

    /configure system security user-params local-user user "admin" access grpc true

    /configure system security aaa local-profiles profile "administrative" grpc rpc-authorization gnoi-cert-mgmt-rotate permit
    /configure system security aaa local-profiles profile "administrative" grpc rpc-authorization gnoi-cert-mgmt-install permit
    /configure system security aaa local-profiles profile "administrative" grpc rpc-authorization gnoi-cert-mgmt-getcert permit
    /configure system security aaa local-profiles profile "administrative" grpc rpc-authorization gnoi-cert-mgmt-revoke permit
    /configure system security aaa local-profiles profile "administrative" grpc rpc-authorization gnoi-cert-mgmt-cangenerate permit
```

Run `commit` to apply these changes.

## Initial Test

With the above config in SR OS , we should now able to test our gNOI cert connectivity from the client to SR OS.

We are going to get a list of existing certificates installed on the router.

```
gnoic -a clab-sros-gnoi-srosA --insecure -u admin -p SReXperts2024 cert get-certs
```

Expected output:

```
+-------------+----+-------------------+------+---------+---------+------------+-------------+----------+
| Target Name | ID | Modification Time | Type | Version | Subject | Valid From | Valid Until | IP Addrs |
+-------------+----+-------------------+------+---------+---------+------------+-------------+----------+
+-------------+----+-------------------+------+---------+---------+------------+-------------+----------+
```

The RPC was executed successfully and no errors were returned. Currently, there are no certificates installed on the router.

## CanGenerateCSR

Let's now test if SR OS can generate a Certificate Signing Request (CSR). If the router can generate the CSR, then it saves us the effort of generating a CSR external to the router and transferring to the router after signing the certificate.

```
gnoic -a clab-sros-gnoi-srosA --insecure -u admin -p SReXperts2024 cert can-generate-csr
```

Expected output:

```
INFO[0005] "clab-sros-gnoi-srosA:57400" key-type=KT_RSA, cert-type=CT_X509, key-size=2048: can_generate: true 
+----------------------------+------------------+
|        Target Name         | Can Generate CSR |
+----------------------------+------------------+
| clab-sros-gnoi-srosA:57400 | true             |
+----------------------------+------------------+
❯ 
```

SR OS can generate the CSR.

## Certificate Authority (CA)

For this tutorial, we are using [Containerlab](https://containerlab.dev/cmd/tools/cert/ca/create/)) to generate the CA certificate and key.

Create a `certs` directory inside the Containerlab directory for this lab and the run the below command from inside the `certs` directory.

```
mkdir clab-sros-gnoi/certs
cd clab-sros-gnoi/certs
```

```
containerlab tools cert ca create
```

Expected output:

```
INFO[0000] Certificate attributes: CN=containerlab.dev, C=Internet, L=Server, O=Containerlab, OU=Containerlab Tools, Validity period=87600h 
```

List the CA certificate and key created by Containerlab.

```
ls -l clab-sros-gnoi/certs
```

Expected output:

```
total 8
-rw-rw-r--+ 1 nokia nokia 1675 Dec 30 20:59 ca.key
-rw-rw-r--+ 1 nokia nokia 1367 Dec 30 20:59 ca.pem
```

## Installing a Certificate

We will be using the gNOI install RPC to generate a certificate from SR OS, sign it using the CA and install it on SR OS. All these using a single command. That's the power of gNOI and gNOIc. For more details on the install command, refer to [gNOIc documentation](https://gnoic.kmrd.dev/command_reference/cert/install/).

```
gnoic -a clab-sros-gnoi-srosA --insecure -u admin -p SReXperts2024 cert --ca-cert clab-sros-gnoi/certs/ca.pem --ca-key clab-sros-gnoi/certs/ca.key install --ip-address 172.20.20.2 --common-name clab-sros-gnoi-srosA --id certalpha
```

Note - the IP address will be included in the SAN field of the certificate.

Expected output:

```
INFO[0000] read local CA certs                          
INFO[0005] "clab-sros-gnoi-srosA:57400" signing certificate "CN=clab-sros-gnoi-srosA" with the provided CA 
INFO[0005] "clab-sros-gnoi-srosA:57400" installing certificate id=certalpha "CN=clab-sros-gnoi-srosA" 
INFO[0005] "clab-sros-gnoi-srosA:57400" Install RPC successful 
```

The certificate is now installed on the router. Let's go ahead and verify this using gnoic.

```
gnoic -a clab-sros-gnoi-srosA --insecure -u admin -p SReXperts2024 cert get-certs
```

Expected output:

```
+----------------------------+-----------+---------------------------+---------+---------+-------------------------+----------------------+----------------------+-------------+
|        Target Name         |    ID     |     Modification Time     |  Type   | Version |         Subject         |      Valid From      |     Valid Until      |  IP Addrs   |
+----------------------------+-----------+---------------------------+---------+---------+-------------------------+----------------------+----------------------+-------------+
| clab-sros-gnoi-srosA:57400 | certalpha | 2024-12-30T21:06:10+02:00 | CT_X509 | 3       | CN=clab-sros-gnoi-srosA | 2024-12-30T18:06:11Z | 2034-12-28T19:06:11Z | 172.20.20.2 |
+----------------------------+-----------+---------------------------+---------+---------+-------------------------+----------------------+----------------------+-------------+
```

We verified that the certificate is installed on the router.

Let's verify the installed certificate on the SR OS node. Installed certificates and keys are found inside `cf3:/system-pki` directory.

```
file list system-pki
```

Expected output:

```
Volume in drive cf3 on slot A is SROS VM.

Volume in drive cf3 on slot A is formatted as FAT32

Directory of cf3:\system-pki

12/30/2024  07:06p      <DIR>          ./
12/30/2024  07:06p      <DIR>          ../
12/30/2024  07:06p                1023 certalpha.crt
12/30/2024  07:06p                1255 certalpha.key
               2 File(s)                   2278 bytes.
               2 Dir(s)               652357632 bytes free.
```

To check certificate content on SR OS:

```
admin system security pki show file-content cf3:/system-pki/certalpha.crt type certificate format der
```

<details>
  <summary>Expected output:</summary>

 ```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            b9:ee:1c:e4:96:15:e2:30:02:4e:0e:c3:47:09:fb:52
        Signature Algorithm: sha512WithRSAEncryption
        Issuer: C=Internet, L=Server, O=Containerlab, OU=Containerlab Tools, CN=containerlab.dev
        Validity
            Not Before: Dec 30 18:06:11 2024 GMT
            Not After : Dec 28 19:06:11 2034 GMT
        Subject: CN=clab-sros-gnoi-srosA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ba:4f:65:c5:d3:a2:1e:a5:70:53:d2:ae:26:1e:
                    e5:c5:8f:15:d3:52:26:93:99:c7:40:c3:45:50:43:
                    f9:d3:bd:a2:a2:3f:c4:22:f9:af:20:ad:0f:45:e7:
                    19:bf:2d:d9:ab:35:fe:72:a8:9c:db:e4:68:62:0a:
                    8e:ee:c5:cf:0c:96:ea:dd:01:d7:05:75:d1:a6:89:
                    0c:a3:4b:00:d5:d4:da:d0:f9:3a:e8:5a:06:59:b4:
                    cc:6a:5b:3c:77:49:11:98:bf:a2:dd:31:90:60:09:
                    bc:85:6e:53:1a:26:96:07:17:46:06:28:77:6b:76:
                    f4:03:57:4a:3c:21:46:14:7e:7b:8d:da:46:04:7c:
                    6a:8e:79:f9:7a:76:25:0a:8d:31:93:59:df:8a:63:
                    96:ea:4b:ec:f4:36:b7:0b:fd:ef:cf:fb:81:be:f0:
                    8b:ce:1a:65:cc:a8:ce:69:54:82:64:9c:2c:24:31:
                    33:37:db:3c:fd:93:83:52:54:cd:c4:02:55:31:c9:
                    12:02:25:ff:37:3b:03:83:01:07:d9:5c:ff:9f:32:
                    30:c2:9e:3c:d4:b5:c1:ea:91:77:1e:de:eb:1a:5e:
                    0d:fe:04:0b:d7:ee:8f:b8:50:99:89:91:15:a5:47:
                    ca:00:49:72:9f:5b:06:45:f4:4a:ea:6f:0f:66:8a:
                    07:77
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication, TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                4A:04:0A:42:87:13:D7:2C:A9:11:FD:7A:89:AC:F6:28:E4:2F:00:91:8D:D7:1C:1E:7C:D4:6C:80:07:A2:9F:D9
            X509v3 Authority Key Identifier: 
                E5:87:1A:D4:F6:16:96:CE:13:37:AC:B9:C4:A0:D9:9F:A5:6D:FB:92
            X509v3 Subject Alternative Name: 
                IP Address:172.20.20.2
    Signature Algorithm: sha512WithRSAEncryption
    Signature Value:
        10:9e:50:0b:7f:ed:9e:2b:e3:3e:9a:5f:9b:55:bc:8f:f7:f2:
        21:49:01:5e:14:64:82:9c:94:c6:f6:66:1e:ef:f1:53:c8:c1:
        d5:4d:70:41:15:20:6b:17:af:e0:62:5c:f6:a1:1b:36:9f:ee:
        e3:55:49:19:8a:29:ca:f8:55:fb:1c:52:ad:4d:ea:14:73:a0:
        98:15:c7:7e:b1:03:68:27:e0:ff:7d:81:86:e6:6c:40:9b:93:
        4d:09:00:5b:61:06:b9:89:4b:bf:83:37:e5:08:71:b6:1c:d1:
        f7:79:36:0b:24:a2:7f:5e:ef:70:a3:f6:c6:b3:ce:7f:c1:d6:
        73:c9:e2:5b:e6:4b:f3:68:f4:9b:cd:ed:a9:f3:b8:7f:bd:31:
        11:a2:0d:24:ca:81:38:41:b7:14:1a:60:9a:3d:c2:de:5b:bf:
        f2:65:bf:ad:05:59:3c:68:2b:db:39:da:ca:f1:08:48:2d:43:
        1f:04:da:de:08:50:32:f7:45:f8:4c:dd:16:4f:b5:19:77:eb:
        4c:4e:fb:90:5a:31:c2:eb:91:f4:ec:7d:1d:4e:1c:e2:34:d7:
        23:b7:e3:f1:5b:86:81:5e:08:90:38:76:08:2c:c1:3c:fe:36:
        1a:0a:37:78:20:29:d7:2c:1d:a1:e4:01:b5:29:d6:10:89:36:
        d9:34:37:6d
```
</details>

## SR OS TLS Configuration

Our next step is to create a TLS profile in SR OS which is used by SR OS to identify the certificate and key to be used. This needs to be configured using SR OS CLI.

First, let's create a `cert-profile` using the certificate and key file names we got in the previous step.

```
    /configure system security tls cert-profile "cert-prof-sros" admin-state enable
    /configure system security tls cert-profile "cert-prof-sros" entry 1 certificate-file "certalpha.crt"
    /configure system security tls cert-profile "cert-prof-sros" entry 1 key-file "certalpha.key"
```

Next, we will create a `cipher-list` indicating which ciphers to use for communication with the client. Make sure to select the right cipher for your implementation or configure all of them.

```
    /configure system security tls server-cipher-list "cipher-sros" tls12-cipher 1 name tls-ecdhe-rsa-aes256-gcm-sha384
```

Finally, we tie all this together in the `tls-profile`.

```
    /configure system security tls server-tls-profile "tls-profile-1" admin-state enable
    /configure system security tls server-tls-profile "tls-profile-1" cert-profile "cert-prof-sros"
    /configure system security tls server-tls-profile "tls-profile-1" cipher-list "cipher-sros"
```

Let's assign this `tls-profile` to be used for all gRPC communication. We will delete the `allow-unsecure-connection` option.

```
    /configure system grpc tls-server-profile "tls-profile-1"
	   /configure system grpc delete allow-unsecure-connection
```

After these changes are committed, we are good to test our TLS connection.

## Testing SR OS TLS connection

Now that SR OS is ready for TLS, let's test a request from client. We will be using [gNMIc](https://gnmic.openconfig.net/) to get the current up time of the SR OS system.

In the gnmic command, we will replace the `insecure` flag with the `tls-ca` flag and provide the name of our CA certificate.

```
gnoic -a clab-sros-gnoi-srosA --insecure -u admin -p SReXperts2024 cert get-certs
```

Expected output:

```
[
  {
    "source": "172.20.20.2",
    "timestamp": 1735586984525929121,
    "time": "2024-12-30T21:29:44.525929121+02:00",
    "updates": [
      {
        "Path": "state/system/up-time",
        "values": {
          "state/system/up-time": "2384550"
        }
      }
    ]
  }
]
```

The communication between the client and SR OS is now secured by TLS.

## Renewing Certificates

gNOI service can also be used for renewing certificates. Certicates are regularly updated before expiry or on an as needed basis. We will use the Rotate RPC for this purpose.

Let's generate a new certificate, sign it and install it on SR OS using the Rotate RPC.

When renewing certificates using Rotate RPC, the certificate id should be same as the existing one.

Before renewing our existing certificate, let's start a gNMI streaming telemetry session in another terminal and we will renew the certificate while this telemetry session is in progress.

We will stream the system uptime every 10s (default).

```
gnmic -a 172.20.20.2 -u admin -p SReXperts2024 --tls-ca clab-sros-gnoi/certs/ca.pem sub --path /state/system/up-time
```

<details>
  <summary>Expected output:</summary>

 ```
{
  "source": "172.20.20.2",
  "subscription-name": "default-1735587694",
  "timestamp": 1735587693897054397,
  "time": "2024-12-30T21:41:33.897054397+02:00",
  "prefix": "state/system",
  "updates": [
    {
      "Path": "up-time",
      "values": {
        "up-time": "3093920"
      }
    }
  ]
}
{
  "sync-response": true
}
```
</details>
