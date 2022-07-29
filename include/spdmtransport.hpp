/**
 * Copyright © 2022 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
};

} // namespace spdm_transport