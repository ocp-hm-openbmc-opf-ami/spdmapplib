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

namespace spdm_transport
{
void SPDMTransportMCTP::transMsgRecvCallback(void*, mctpw::eid_t srcEid,
                                             bool /*tagOwner*/,
                                             uint8_t /* msgTag*/,
                                             const std::vector<uint8_t>& data,
                                             int /*status*/)
{
    if (!data.empty() &&
        data.at(0) == static_cast<uint8_t>(mctpw::MessageType::spdm))
    {
        TransportEndPoint tmpEP;
        tmpEP.devIdentifier = srcEid;
        msgReceiveCB(tmpEP, data);
    }
};

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

void SPDMTransportMCTP::setListener(MsgReceiveCallback msgRcvCB)
{
    msgReceiveCB = msgRcvCB;
}

void SPDMTransportMCTP::transRemoveDevice(const mctpw::eid_t eid)
{
    TransportEndPoint tmpEP;
    tmpEP.devIdentifier = eid;

    if (onDeviceUpdtCB)
    {
        onDeviceUpdtCB(tmpEP, Event::removed);
    }
}

void SPDMTransportMCTP::transAddNewDevice(const mctpw::eid_t eid)
{
    TransportEndPoint tmpEP;
    tmpEP.devIdentifier = eid;
    if (onDeviceUpdtCB)
    {
        onDeviceUpdtCB(tmpEP, Event::added);
    }
}

int SPDMTransportMCTP::asyncSendData(TransportEndPoint& transEP,
                                     const std::vector<uint8_t>& request,
                                     uint64_t /*timeout*/)
{
    mctpw::eid_t eid = transEP.devIdentifier;

    boost::asio::spawn(*(ioc), [this, eid,
                                request](boost::asio::yield_context yield) {
        mctpWrapper->sendYield(yield, eid,
                               static_cast<uint8_t>(mctpw::MessageType::spdm),
                               false, request);
    });

    return spdm_app_lib::error_codes::returnSuccess;
}

int SPDMTransportMCTP::sendRecvData(TransportEndPoint& transEP,
                                    const std::vector<uint8_t>& request,
                                    uint64_t timeout,
                                    std::vector<uint8_t>& responsePacket)
{
    constexpr std::chrono::milliseconds sendReceiveBlockedTimeout{1000};
    mctpw::eid_t eid = transEP.devIdentifier;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("SPDMTransportMCTP::syncSendRecvData eid: " + std::to_string(eid) +
         ", request size: " + std::to_string(request.size()) +
         ", timeout: " + std::to_string(timeout))
            .c_str());
    std::pair<boost::system::error_code, mctpw::ByteArray> reply;
    try
    {
        reply = mctpWrapper->sendReceiveBlocked(eid, request,
                                                sendReceiveBlockedTimeout);
    }
    catch (const std::exception& exceptionIn)
    {
        std::string exceptionStr = exceptionIn.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SPDMTransportMCTP::sendRecvData Exception: " + exceptionStr)
                .c_str());
        return spdm_app_lib::error_codes::generalReturnError;
    }
    if (reply.first)
    {
        return reply.first.value();
    }
    else
    {
        responsePacket = reply.second;
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
        return spdm_app_lib::error_codes::returnSuccess;
    }
}

void SPDMTransportMCTP::initDiscovery(
    std::function<void(spdm_transport::TransportEndPoint eidPoint,
                       spdm_transport::Event event)>
        onDeviceUpdateCB)
{
    onDeviceUpdtCB = onDeviceUpdateCB;

    boost::asio::spawn(*(ioc), [this](boost::asio::yield_context yield) {
        mctpWrapper->detectMctpEndpoints(yield);
        mctpw::VersionFields specVersion = {0xF1, 0xF0, 0xF1, 0x00};
        auto rcvStatus = mctpWrapper->registerResponder(specVersion);
        if (rcvStatus != boost::system::errc::success)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "SPDMTransportMCTP::initDiscovery registerResponder Failed");
        }
        mctpw::MCTPWrapper::EndpointMap eidMap = mctpWrapper->getEndpointMap();
        for (auto& item : eidMap)
        {
            transAddNewDevice(item.first);
        }
    });
}

SPDMTransportMCTP::SPDMTransportMCTP(
    std::shared_ptr<boost::asio::io_service> io,
    std::shared_ptr<sdbusplus::asio::connection> con,
    mctpw::BindingType tranType) :
    ioc(io),
    conn(con), transType(tranType)
{
    using namespace std::placeholders;
    mctpw::MCTPConfiguration config(mctpw::MessageType::spdm, transType);
    mctpWrapper = std::make_shared<mctpw::MCTPWrapper>(
        conn, config,
        std::bind(&SPDMTransportMCTP::transOnDeviceUpdate, this, _1, _2, _3),
        std::bind(&SPDMTransportMCTP::transMsgRecvCallback, this, _1, _2, _3,
                  _4, _5, _6));
}
} // namespace spdm_transport
