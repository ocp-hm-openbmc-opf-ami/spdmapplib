# spdmapplib: SPDM Application Library

The purpose of the “SPDM Application Library” is to provide abstraction of 
Secure Protocol Data Modelling (SPDM) API commands.
Logical transport layer is encapsulated in easy-to-use wrappers,
while underlying physical transport layer is left to be implemented
by library user.

“SPDM Application Library”  is designed for applications that requires SPDM 
responder and requester functions.
The `spdmapplib` wrap libspdm(DMTP DSP0274 1.0.0) in easy-to-use way for users.  

In the package, it also include transport layer example based on 
`MCTP over SMBus` for SPDM devices.
Other transport channel can follow same transport layer abstraction to 
implement their own transport layer.

## SPDM Application library concept diagram

```text
       +==============+           +==============+
       |SPDM Responder|           |SPDM Requester|                    //SPDM Applications
       |    Daemon    |           |  Application |
       +==============+           +==============+
              |                       |      ^
===================================================================
              v                       v      |                        //Main SPDMAppLib 
   +-----------------------------------------+---------+
   |                                                   |
   |                    SPDMAppLib                     |
   |                                 +-----------------+---------+
   +----------+----------------------+libSPDM CallBack Functions |
              |                ^     +---------------------------+
              |                |                v       ^
              |                |          +-------------------+
              |                |          |                   |
              |                |          |    libSPDM(DMTF)  |
              |                |          |                   |
              |                |          +-------------------+
              |                |
===================================================================
              v                |                                      //SPDM Transport Layer
    +--------------------------+---------+
    |                                    |
    |            SPDMTransport           |
    |                                    |
    +---+---------------------+----------+
        |      ^              |      ^
        v      |              v      |
     +---------+-+         +---------+--+
     | mctpwplus |         |   Other    |
     |  (MCTP)   |         |  Trasport  |
     +-----------+         +------------+
        v     ^               v      ^
 +--------------------+  +-------------------+
 |   PCIe/SMBus BUS   |  |    Other BUS      |
 +--------------------+  +-------------------+
   v  ^       v  ^          v  ^      v  ^
  +------+  +------+      +------+  +------+
  | SPDM |  | SPDM |      | SPDM |  | SPDM |
  |Device|  |Device|      |Device|  |Device|
  +------+  +------+      +------+  +------+
```

## Prerequisites

`spdmapplib` is based on the libspdm library which is maintained in

<https://github.com/DMTF/libspdm>

The MCTP trasport layer is based on the mctpwplus which is maintained in

<https://github.com/intel-collab/firmware.bmc.openbmc.libraries.mctpwplus>

The EntityManager configurations should be maintained for responder and 
requester applications.

## Background and References

- DMTF DSP0274 1.0.0, Security Protocol and Data Model (SPDM) Specification.

## SPDM Requester Interface
[SPDMAppLib.pdf](./SPDMAppLib.pdf) chapter 6.3.

## SPDM Responder Interface
[SPDMAppLib.pdf](./SPDMAppLib.pdf) chapter 6.5.

## Transport Layer Interface
[SPDMAppLib.pdf](./SPDMAppLib.pdf) chapter 6.7.

## Entity Manager Configuration
Example configurations.
```json
    {
        "Role": "responder",
        "Version": "1.0",
        "CertPath": "/usr/bin",
        "Capability": [
            "CACHE",
            "CERT",
            "CHAL",
            "MEAS_SIG",
            "MEAS_FRESH"
        ],
        "Hash": [
            "SHA_384"
        ],
        "MeasHash": [
            "SHA_384"
        ],
        "Asym": [
            "ECDSA_P384",
            "ECDSA_P256"
        ],
        "ReqAsym": [
            "RSAPSS_3072",
            "RSAPSS_2048",
            "RSASSA_3072",
            "RSASSA_2048"
        ],
        "Dhe": [ 
            "SECP_384_R1",
            "SECP_256_R1",
            "FFDHE_3072","FFDHE_2048"
        ],
        "Aead": [
            "AES_256_GCM",
            "CHACHA20_POLY1305"
        ],
        "BasicMutAuth": "BASIC",
        "MutAuth": "W_ENCAP",
        "Type": "SPDMConfiguration",
        "Name": "SPDM responder"
    },
    {
        "Role": "requester",
        "Version": "1.0",
        "CertPath": "/usr/bin",
        "Capability": [
            "CERT",
            "CHAL"
        ],
        "Hash": [
            "SHA_384"
        ],
        "MeasHash": [
            "SHA_384"
        ],
        "Asym": [
            "ECDSA_P384"
        ],
        "ReqAsym": [
            "RSAPSS_3072",
            "RSAPSS_2048",
            "RSASSA_3072",
            "RSASSA_2048"
        ],
        "Dhe": [ 
            "SECP_384_R1",
            "SECP_256_R1",
            "FFDHE_3072","FFDHE_2048"
        ],
        "Aead": [
            "AES_256_GCM",
            "CHACHA20_POLY1305"
        ],
        "BasicMutAuth": "BASIC",
        "MutAuth": "W_ENCAP",
        "Type": "SPDMConfiguration",
        "Name": "SPDM requester"
    }
```

## SPDM Transport creation diagram

```text
┌───────────────────────────────────────────────────┐
│                                                   │
│     SPDM Responder/Requester Applications         │
│                                                   │
└─────────────┬─────────────────────────────┬───────┘
              │                             │
              │                         <creates>
              │                             │
              │                   ┌─────────▼─────────┐
              │        <injects>  │                   │
              │◄──────────────────┤ SPDMTransportMCTP │
              │                   │                   │
              ▼                   └───────────────────┘
              │
       <instantiates>
              │
--------------│---------[spdmapplib]------------------------
              │
┌─────────────▼────────────┐
│                          │
│    SPDMResponderImpl     │
│    SPDMRequesterImpl     │
│                          │
└─────────────┬────────────┘
         <inherits>
              │
┌─────────────▼─────────────┐
│                           │
│ spdmapplib::SPDMResponder │
│ spdmapplib::SPDMRequester │
│                           │
└───────────────────────────┘
```

## Requester Application Example
<https://github.com/intel-collab/firmware.bmc.openbmc.libraries.spdmapplib/tree/main/utility>

## Responder daemon Example
<https://github.com/intel-collab/firmware.bmc.openbmc.applications.spdmd>