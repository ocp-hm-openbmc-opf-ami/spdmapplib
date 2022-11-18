/*
// Copyright (c) 2022 Intel Corporation
//
// This software and the related documents are Intel copyrighted
// materials, and your use of them is governed by the express license
// under which they were provided to you ("License"). Unless the
// License provides otherwise, you may not use, modify, copy, publish,
// distribute, disclose or transmit this software or the related
// documents without Intel's prior written permission.
//
// This software and the related documents are provided as is, with no
// express or implied warranties, other than those that are expressly
// stated in the License.
*/

#pragma once
#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
namespace spdm_transport
{
/**
 * @brief These events are triggered when
 * endPoints are added or removed
 *
 */
enum class Event
{
    added,
    removed
};

/**
 * @brief Defined callback function prototype
 *
 * @param transEP The TransportEndPoint object.
 * @param data Pointer to a buffer.
 */
struct TransportEndPoint;
using MsgReceiveCallback = std::function<void(
    TransportEndPoint& transEP, const std::vector<uint8_t>& data)>;
using OnDeviceCallback = std::function<void(
    spdm_transport::TransportEndPoint eidPoint, spdm_transport::Event event)>;
/**
 * @brief Endpoint information, could be extended.
 *
 */
struct TransportEndPoint
{
    uint8_t devIdentifier;
    bool operator==(const TransportEndPoint& secondDevice) const
    {
        const TransportEndPoint& firstDevice = (*this);
        return firstDevice.devIdentifier == secondDevice.devIdentifier;
    }
};

/**
 * @brief SPDM transport layer class.
 *
 **/

class SPDMTransport
{
  public:
    virtual ~SPDMTransport() = default;
    /* APIs for requester and responder */
    /**
     * @brief The function is responsible for doing discovery of the endPoints
     * @param  callback
     **/
    virtual void initDiscovery(std::function<void(TransportEndPoint endPoint,
                                                  spdm_transport::Event event)>
                                   onEndPointChange) = 0;

    /****************************************************
        APIs to responder and interface that implementation should override
    these pure virtual functions
    ******************************************************/
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

    /**
     * @brief Defines the default underlying transport
     *
     * @return std::string default
     */
    virtual std::string getSPDMtransport()
    {
        return "default";
    }
};

} // namespace spdm_transport
