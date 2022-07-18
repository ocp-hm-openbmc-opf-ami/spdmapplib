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
 * limitation
 */
#include "spdmtransport_mctp.hpp"

#include <phosphor-logging/log.hpp>

#include <cstdint>
#include <functional>
#include <iostream>

namespace spdmtransport
{
/*Callback function for MCTPwplus  */
/**
 * @brief Function registered to mctpwrapper as receiving message Callback.
 *
 **/
void SPDMTransportMCTP::transMsgRecvCallback(void*, mctpw::eid_t srcEid,
                                             bool /*tagOwner*/,
                                             uint8_t /* msgTag*/,
                                             const std::vector<uint8_t>& data,
                                             int /*status*/)
{
    if (!data.empty() &&
        data.at(0) == static_cast<uint8_t>(mctpw::MessageType::spdm))
    { // only SPDM message arrive here.
        TransportEndPoint tmpEP;
        tmpEP.devIdentifier = srcEid;
        msgReceiveCB(tmpEP, data);
    }
};

/**
 * @brief Function registered to mctpwrapper as device update handler.
 *
 **/
void SPDMTransportMCTP::transOnDeviceUpdate(
    void*, const mctpw::Event& evt, boost::asio::yield_context /*yield*/)
{
    switch (evt.type)
    {
        case mctpw::Event::EventType::deviceAdded:
            transAddNewDevice(evt.eid);
            break;
        case mctpw::Event::EventType::deviceRemoved:
            transRemoveDevice(evt.eid);
        default:
            break;
    }
    return;
}

/*Implement SPDM transport layer */

/**
 * @brief Initial function of transport instance
 *
 * @param  ioc                shared_ptr to boost io_context object.
 * @param  conn              shared_ptr to already existing boost
 *asio::connection.
 * @param  addCB             The callback function for new endpoint
 *detected.
 * @param  delCB             The callback function for EndPoint removed.
 * @param  msgRcvCB          The callback function for messages received(for
 *responder used).
 * @return 0: success, other: failed.
 **/

void SPDMTransportMCTP::registerCallback(MsgReceiveCallback msgRcvCB)
{
    using namespace std::placeholders;
    msgReceiveCB = msgRcvCB;
}

/**
 * @brief Called by mctpwrapper when device updated.
 *
 * @param  eid          The EID of detected new endpoint.
 * @return true: success, false: failed.
 **/
int SPDMTransportMCTP::transRemoveDevice(const mctpw::eid_t eid)
{
    TransportEndPoint tmpEP;
    tmpEP.devIdentifier = eid;

    if (onDeviceUpdtCB)
    {
        boost::asio::spawn(*(pioc),
                           [this, tmpEP](boost::asio::yield_context yield) {
                               onDeviceUpdtCB(yield, tmpEP, Event::removed);
                           });
    }
    return eid;
}

/**
 * @brief Called by mctpwrapper when device updated.
 *
 * @param  eid          The EID of detected new endpoint.
 * @return true: success, false: failed.
 **/
int SPDMTransportMCTP::transAddNewDevice(const mctpw::eid_t eid)
{
    TransportEndPoint tmpEP;
    // tmpEP.transType = transType;
    tmpEP.devIdentifier = eid;
    if (onDeviceUpdtCB)
    {
        boost::asio::spawn(*(pioc),
                           [this, tmpEP](boost::asio::yield_context yield) {
                               onDeviceUpdtCB(yield, tmpEP, Event::added);
                           });
    }
    return eid;
}

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
int SPDMTransportMCTP::asyncSendData(TransportEndPoint& transEP,
                                     const std::vector<uint8_t>& request,
                                     uint64_t /*timeout*/)
{
    mctpw::eid_t eid = transEP.devIdentifier;

    boost::asio::spawn(*(pioc), [this, eid,
                                 request](boost::asio::yield_context yield) {
        mctpWrapper->sendYield(yield, eid,
                               static_cast<uint8_t>(mctpw::MessageType::spdm),
                               false, request);
    });

    return spdmapplib::errorcodes::returnSuccess;
}

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
int SPDMTransportMCTP::sendRecvData(TransportEndPoint& transEP,
                                    const std::vector<uint8_t>& request,
                                    uint64_t timeout,
                                    MsgReceiveCallback rspRcvCB)
{
    constexpr std::chrono::milliseconds sendReceiveBlockedTimeout{500};
    mctpw::eid_t eid = transEP.devIdentifier;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("SPDMTransportMCTP::syncSendRecvData eid: " + std::to_string(eid) +
         ", request size: " + std::to_string(request.size()) +
         ", timeout: " + std::to_string(timeout))
            .c_str());
    auto reply = mctpWrapper->sendReceiveBlocked(eid, request,
                                                 sendReceiveBlockedTimeout);
    if (reply.first)
    {
        return reply.first.value();
    }
    else
    {
        std::vector<uint8_t> responsePacket = reply.second;
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("SPDMTransportMCTP::syncSendRecvData send recv :response_vector.size():" +
             std::to_string(responsePacket.size()))
                .c_str());
        std::stringstream ss;
        ss << std::uppercase << std::hex << std::endl;
        for (unsigned int i = 0; i < responsePacket.size(); ++i)
        {
            ss << std::setfill('0') << std::setw(3)
               << static_cast<uint16_t>(responsePacket[i]);
            if ((i % 32) == 0)
            {
                ss << '\n';
            }
            else
            {
                ss << ' ';
            }
        }
        ss << std::endl;
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ss.str().c_str());

        rspRcvCB(transEP, responsePacket);

        return spdmapplib::errorcodes::returnSuccess;
    }
}

void SPDMTransportMCTP::initDiscovery(
    std::function<void(boost::asio::yield_context yield,
                       spdmtransport::TransportEndPoint eidPoint,
                       spdmtransport::Event event)>
        onDeviceUpdateCB)
{
    using namespace std::placeholders;
    onDeviceUpdtCB = onDeviceUpdateCB;

    boost::asio::spawn(*(pioc), [this](boost::asio::yield_context yield) {
        std::cerr << "Registering a SMBus SPDM responder" << std::endl;
        mctpw::VersionFields specVersion = {0xF1, 0xF1, 0xF0, 0};
        auto rcvStatus = mctpWrapper->registerResponder(specVersion);
        if (rcvStatus == boost::system::errc::success)
        {
            std::cerr << "Success" << '\n';
        }
        else
        {
            std::cerr << "Failed \n";
        }
        mctpWrapper->detectMctpEndpoints(yield);
        mctpw::MCTPWrapper::EndpointMap eidMap = mctpWrapper->getEndpointMap();
        for (auto& item : eidMap)
        {
            transAddNewDevice(item.first);
        }
    });
}

SPDMTransportMCTP::SPDMTransportMCTP(
    std::shared_ptr<boost::asio::io_service> io,
    std::shared_ptr<sdbusplus::asio::connection> conn,
    mctpw::BindingType tranType) :
    pioc(io),
    pconn(conn), transType(tranType)
{
    using namespace std::placeholders;
    mctpw::MCTPConfiguration config(mctpw::MessageType::spdm, transType);
    mctpWrapper = std::make_shared<mctpw::MCTPWrapper>(
        pconn, config,
        std::bind(&SPDMTransportMCTP::transOnDeviceUpdate, this, _1, _2, _3),
        std::bind(&SPDMTransportMCTP::transMsgRecvCallback, this, _1, _2, _3,
                  _4, _5, _6));
}
} // namespace spdmtransport
