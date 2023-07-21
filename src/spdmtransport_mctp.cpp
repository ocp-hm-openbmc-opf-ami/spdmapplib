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

#include "spdmtransport_mctp.hpp"

#include <phosphor-logging/log.hpp>

#include <cstdint>
#include <functional>
#include <iostream>
#include <sstream>

namespace spdm_transport
{
void SPDMTransportMCTP::transMsgRecvCallback(void*, mctpw::eid_t srcEid,
                                             bool /*tagOwner*/,
                                             uint8_t /* msgTag*/,
                                             const std::vector<uint8_t>& data,
                                             int status)
{
    if (data.empty())
    {
        return;
    }

    TransportEndPoint tmpEP;
    tmpEP.devIdentifier = srcEid;

    if (data.at(0) == static_cast<uint8_t>(mctpw::MessageType::spdm))
    {
        msgReceiveCB(tmpEP, data);
    }
    else if (data.at(0) == static_cast<uint8_t>(mctpw::MessageType::securedMsg))
    {
        std::stringstream ss;
        ss << "onMCTPReceive EID " << static_cast<int>(srcEid) << std::endl
           << "onMCTPReceive Status " << status << std::endl
           << "onMCTPReceive Response ";
        for (uint8_t n : data)
        {
            ss << n << ' ';
        }
        phosphor::logging::log<phosphor::logging::level::DEBUG>(ss.str().c_str());
        if (asyncSendData(tmpEP, data, 2000) !=
            spdm_app_lib::error_codes::returnSuccess)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to send secured messages back.");
        }
    }
}

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
                                    uint64_t /*timeout*/,
                                    std::vector<uint8_t>& responsePacket)
{
    constexpr std::chrono::milliseconds sendReceiveBlockedTimeout{1000};
    mctpw::eid_t eid = transEP.devIdentifier;
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
        return spdm_app_lib::error_codes::generalReturnError;
    }

    if (reply.second.at(0) != static_cast<uint8_t>(mctpw::MessageType::spdm) &&
        reply.second.at(0) !=
            static_cast<uint8_t>(mctpw::MessageType::securedMsg))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    responsePacket.clear();
    responsePacket = reply.second;
    return spdm_app_lib::error_codes::returnSuccess;
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

    boost::asio::spawn(*(ioc), [this](boost::asio::yield_context yield) {
        securedOverMctpWrapper->detectMctpEndpoints(yield);
        mctpw::VersionFields specVersion = {0xF1, 0xF0, 0xF1, 0x00};
        auto rcvStatus = securedOverMctpWrapper->registerResponder(specVersion);
        if (rcvStatus != boost::system::errc::success)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to register secured MCTP responder.");
        }
    });
}

std::string SPDMTransportMCTP::getSPDMtransport()
{
    return "mctp";
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
    mctpw::MCTPConfiguration securedConfig(mctpw::MessageType::securedMsg,
                                           transType);
    securedOverMctpWrapper = std::make_shared<mctpw::MCTPWrapper>(
        conn, securedConfig,
        std::bind(&SPDMTransportMCTP::transOnDeviceUpdate, this, _1, _2, _3),
        std::bind(&SPDMTransportMCTP::transMsgRecvCallback, this, _1, _2, _3,
                  _4, _5, _6));
}
} // namespace spdm_transport
