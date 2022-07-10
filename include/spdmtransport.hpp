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
namespace spdmtransport
{
/**
 * @brief Define callback function prototype
 *
 * @param transEP The transportEndPoint object.
 * @param data Pointer to a buffer.
 */
struct transportEndPoint;
using MsgReceiveCallback = std::function<void(
    transportEndPoint& transEP, const std::vector<uint8_t>& data)>;
using AddRemoveDeviceCallback = std::function<int(transportEndPoint& transEP)>;

/**
 * @brief SPDM Transport type, could be extended.
 *
 */
enum class TransportIdentifier : uint8_t
{
    mctpOverSMBus = 0x01,
    mctpOverPCIe = 0x02,
    pmtWatcher = 0x03, /*Intel specific transport*/
};

/**
 * @brief Endpoint information, could be extended.
 *
 */
struct transportEndPoint
{
    TransportIdentifier transType; /*interface type.*/
    uint8_t devIdentifier;
    bool operator==(const transportEndPoint& p2) const
    {
        const transportEndPoint& p1 = (*this);
        return p1.transType == p2.transType &&
               p1.devIdentifier == p2.devIdentifier;
    }
};

/**
 * @brief SPDM transport layer class.
 *
 **/

class spdmTransport
{
  public:
    virtual ~spdmTransport() = default;

    /* APIs for requester and responder */
    /**
     * @brief Initial function of transport instance
     *
     * @param  ioc               shared_ptr to boost io_context object.
     * @param  conn              shared_ptr to already existing boost
     *asio::connection.
     * @param  addCB             The callback function for new endpoint
     *detected.
     * @param  delCB             The callback function for EndPoint removed.
     * @param  msgRcvCB          The callback function for messages received(for
     *responder used).
     * @return 0: success, other: failed.
     **/
    virtual int initTransport(
        std::shared_ptr<boost::asio::io_context> ioc,
        std::shared_ptr<sdbusplus::asio::connection> conn,
        AddRemoveDeviceCallback addCB, AddRemoveDeviceCallback delCB,
        MsgReceiveCallback msgRcvCB =
            nullptr) = 0; // override this function in implementation

    /**
     * @brief Get the interface type of transport layer
     * @return TransportIdentifier
     *
     **/
    virtual TransportIdentifier getTransType(void) = 0;

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
     * @return 0: success, other: failed.
     *
     **/
    virtual int asyncSendData(transportEndPoint& transEP,
                              const std::vector<uint8_t>& request,
                              uint64_t timeout) = 0;

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
     * @param  rspRcvCB          The resRcvCB to be called when response data
     *received.
     * @return 0: success, other: failed.
     *
     **/
    virtual int syncSendRecvData(transportEndPoint& transEP,
                                 const std::vector<uint8_t>& request,
                                 uint64_t timeout,
                                 MsgReceiveCallback rspRcvCB) = 0;
};

} // namespace spdmtransport