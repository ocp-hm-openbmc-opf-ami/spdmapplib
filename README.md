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

Defined required APIs for SPDMRequester listed below, detail information is in the file [spdmapplib.hpp](./include/spdmapplib.hpp).


```c++
    /**
     * @brief Initial function of SPDM requester
     *
     * @param  ioc               The shared_ptr to boost io_context object.
     * @param  conn              The shared_ptr of sdbusplus conn.
     * @param  trans             The pointer of transport instance.
     * @param  ptransResponder   The pointer to assigned responder EndPoint.
     * @param  pSpdmConfig       Configuration read from entity-manager.
     *
     **/
    SPDMRequester(std::shared_ptr<boost::asio::io_context> ioc,
                  std::shared_ptr<sdbusplus::asio::connection> conn,
                  std::shared_ptr<spdm_transport::SPDMTransport> trans,
                  spdm_transport::TransportEndPoint& endPoint,
                  SPDMConfiguration& spdmConfig);
    /**
     * @brief Get all measurement function
     *
     * @param   measurements     The certificate returned for specific endPoint
     * @return  true             Indicates Success.
     * @return  false            Indicates Failure
     **/
    bool getMeasurements(std::vector<uint8_t>& certificate);

    /**
     * @brief Get certificate function
     *
     * @param   measurements     The certificate returned for specific endPoint.
     * @return  true             Indicates Success.
     * @return  false            Indicates Failure
     *
     **/
    bool getCertificate(std::vector<uint8_t>& measurements);
```

## SPDM Responder Interface

Defined required APIs for SPDMResponder listed below, detail information is in the file [spdmapplib.hpp](./include/spdmapplib.hpp).

```c++
  /**
     * @brief Initial function of SPDM responder
     *  When the function is called, it will enter daemon mode and never return.
     *
     * @param  ioc                boost io_context object.
     * @param  conn              The Pointer to sdbusplus conn.
     * @param  trans             The pointer of transport instance.
     * @param  spdmConfig        Application assigned SPDMConfiguration.
     **/
    SPDMResponder(std::shared_ptr<boost::asio::io_context> ioc,
                  std::shared_ptr<sdbusplus::asio::connection> conn,
                  std::shared_ptr<spdm_transport::SPDMTransport> trans,
                  SPDMConfiguration& spdmConfig);

    bool updateSPDMPool(spdm_transport::TransportEndPoint& endPoint);
```

## Transport Layer Interface

Defined required APIs for SPDMTransport listed below, detail information is in the file [spdmtransport.hpp](./include/spdmtransport.hpp).

```c++
    /**
     * @brief The function is responsible for doing discovery of the endPoints
     * @param  callback
     **/
    virtual void initDiscovery(std::function<void(TransportEndPoint endPoint,
                                                  spdm_transport::Event event)>
                                   onEndPointChange) = 0;
    /**
     * @brief The async send data function for responder
     *  nonblocking function to send message to remote endpoint.
     *
     * @param  transEP           The destination endpoint.
     * @param  request           The vector of payload.
     * @param  timeout           The timeout time.
     * @return 0                 Send is successful
     * @return other values      Send failed
     *
     **/
    virtual int asyncSendData(TransportEndPoint& transEP,
                              const std::vector<uint8_t>& request,
                              uint64_t timeout) = 0;

    /**
     * @brief set Listener for the messages received
     *
     * @param  msgRcvCB          Listener for async messages
     **/
    virtual void
        setListener(MsgReceiveCallback msgRcvCB) = 0; // override this function
                                                      // in implementation
    /****************************************************
        APIs for requester
    ******************************************************/
    /**
     * @brief The sync send and receive data function for requester
     *  blocking function to send SPDM payload and get response data.
     *
     * @param  transEP           The destination endpoint.
     * @param  request           The vector of data payload.
     * @param  timeout           The timeout time.
     * @param  rspRcvCB          The resRcvCB when response data received.
     * @return 0                 Send is successful
     * @return other values      Send failed
     **/
    virtual int sendRecvData(TransportEndPoint& transEP,
                             const std::vector<uint8_t>& request,
                             uint64_t timeout,
                             std::vector<uint8_t>& response) = 0;
```

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
        "SlotCount": "3",
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
        "SlotCount": "3",
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