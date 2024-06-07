# SR OS gNOI certificate management
This tutorial is on gRPC gNOI certificate management in SR OS.

gNOI is a gRPC service for performing operations on the router. For more details, please visit [gNOI Openconfig page](https://github.com/openconfig/gnoi/tree/main).

For more details on SR OS implementation of gRPC services, refer to [SR OS Documentation] (https://documentation.nokia.com/sr/24-3/7x50-shared/system-management/grpc.html)

## Client
We will be using [gnoic](https://gnoic.kmrd.dev/) as the client. Refer to the page for installation procedure.

Verify gnoic is installed on your client.

```
# gnoic version
version : 0.0.21
 commit : bc327f6
   date : 2024-04-25T00:20:06Z
 gitURL : https://github.com/karimra/gnoic
   docs : https://gnoic.kmrd.dev
```

## SR OS Configuration

This tutorial is based on SR OS release `24.3R2`.

On the SR OS side, gRPC should be enabled along with gNOI Cert operation. On the user configuration, gRPC should be allosed and gNOI cert operations should also be permitted in the user profile.

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

## Initial Test

With the above config in SR OS , we should now able to test our gNOI cert connectivity from the client to SR OS.

We are going to get a list of existing certificates installed on the router.

```
# gnoic -a clab-srexperts-p1 --insecure -u admin -p SReXperts2024 cert get-certs
+-------------+----+-------------------+------+---------+---------+------------+-------------+----------+
| Target Name | ID | Modification Time | Type | Version | Subject | Valid From | Valid Until | IP Addrs |
+-------------+----+-------------------+------+---------+---------+------------+-------------+----------+
+-------------+----+-------------------+------+---------+---------+------------+-------------+----------+
```

The RPC was executed successfully and no errors were returned. Currently, there are no certificates installed on the router.

## CanGenerateCSR

Let's now test if SR OS can generate a Certificate Signing Request (CSR). If the router can generate the CSR, then it saves the effort of generating a CSR external to the router and transferring to the router after signing the certificate.

```
# gnoic -a clab-srexperts-p1 --insecure -u admin -p SReXperts2024 cert can-generate-csr
INFO[0000] "clab-srexperts-p1:57400" key-type=KT_RSA, cert-type=CT_X509, key-size=2048: can_generate: true 
+-------------------------+------------------+
|       Target Name       | Can Generate CSR |
+-------------------------+------------------+
| clab-srexperts-p1:57400 | true             |
+-------------------------+------------------+
```

SR OS can generate the CSR.

## Certificate Authority (CA)

For this tutorial, we using [Containerlab](https://containerlab.dev/cmd/tools/cert/ca/create/)) to generate the CA certificate and key.

```
# containerlab tools cert ca create
INFO[0000] Certificate attributes: CN=containerlab.dev, C=Internet, L=Server, O=Containerlab, OU=Containerlab Tools, Validity period=87600h 
```

## Installing a Certificate

We will be using the gNOI install RPC to generate a certificate from SR OS, sign it using the CA and install it on SR OS. All these using a single command. That's the power of gNOI and gNOIc. For more details on the install command, refer to [gNOIc documentation](https://gnoic.kmrd.dev/command_reference/cert/install/).

```
# gnoic -a clab-srexperts-p1 --insecure -u admin -p SReXperts2024 cert --ca-cert ca.pem --ca-key ca.key install --ip-address 172.31.255.30 --common-name clab-srexperts-p1 --id certalpha
INFO[0000] read local CA certs                          
INFO[0000] "clab-srexperts-p1:57400" signing certificate "CN=clab-srexperts-p1" with the provided CA 
INFO[0000] "clab-srexperts-p1:57400" installing certificate id=certalpha "CN=clab-srexperts-p1" 
INFO[0000] "clab-srexperts-p1:57400" Install RPC successful 
```

The certificate is now installed on the router. Let's go ahead and verify this using gnoic.

```
# gnoic -a clab-srexperts-p1 --insecure -u admin -p SReXperts2024 cert get-certs
+-------------------------+-----------+---------------------------+---------+---------+----------------------+----------------------+----------------------+---------------+
|       Target Name       |    ID     |     Modification Time     |  Type   | Version |       Subject        |      Valid From      |     Valid Until      |   IP Addrs    |
+-------------------------+-----------+---------------------------+---------+---------+----------------------+----------------------+----------------------+---------------+
| clab-srexperts-p1:57400 | certalpha | 2024-06-07T23:35:14+03:00 | CT_X509 | 3       | CN=clab-srexperts-p1 | 2024-06-07T19:35:47Z | 2034-06-05T20:35:47Z | 172.31.255.30 |
+-------------------------+-----------+---------------------------+---------+---------+----------------------+----------------------+----------------------+---------------+
```

We verified that the certificate is installed on the router.





