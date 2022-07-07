/**
 * Copyright © 2020 Intel Corporation
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
void spdmTransportMCTP::transMsgRecvCallback(void*, mctpw::eid_t srcEid, bool,
                                             uint8_t,
                                             const std::vector<uint8_t>& data,
                                             int)
{
    if (!data.empty() &&
        data.at(0) == static_cast<uint8_t>(mctpw::MessageType::spdm))
    { // only SPDM message arrive here.
        transportEndPoint tmpEP;
        tmpEP.devIdentifer = srcEid;
        tmpEP.transType = getTransType();
        msgReceiveCB(&tmpEP, data);
    }
};

/**
 * @brief Function registered to mctpwrapper as device update handler.
 *
 **/
void spdmTransportMCTP::transOnDeviceUpdate(void*, const mctpw::Event& evt,
                                            boost::asio::yield_context yield)
{
    UNUSED(yield);
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
 * @param  io                boost io_service object.
 * @param  conn              shared_ptr to already existing boost
 *asio::connection.
 * @param  addCB             The callback function for new endpoint
 *detected.
 * @param  delCB             The callback function for EndPoint removed.
 * @param  msgRcvCB          The callback function for messages received(for
 *responder used).
 * @return 0: success, other: failed.
 **/
int spdmTransportMCTP::initTransport(
    std::shared_ptr<boost::asio::io_service> io,
    std::shared_ptr<sdbusplus::asio::connection> conn,
    AddRemoreDeviceCallback addCB, AddRemoreDeviceCallback delCB,
    MsgReceiveCallback msgRcvCB)
{
    using namespace std::placeholders;
    pio = io;
    pconn = conn;
    addNewDeviceCB = addCB;
    removeDeviceCB = delCB;
    msgReceiveCB = msgRcvCB;
    mctpw::BindingType bindingType;
    if (transType == spdmtransport::TransportIdentifier::mctpOverSmBus)
    {
        bindingType = mctpw::BindingType::mctpOverSmBus;
    }
    else
    {
        bindingType = mctpw::BindingType::mctpOverPcieVdm;
    }
    mctpw::MCTPConfiguration config(mctpw::MessageType::spdm, bindingType);
    mctpWrapper = std::make_shared<mctpw::MCTPWrapper>(
        conn, config,
        std::bind(&spdmTransportMCTP::transOnDeviceUpdate, this, _1, _2, _3),
        std::bind(&spdmTransportMCTP::transMsgRecvCallback, this, _1, _2, _3,
                  _4, _5, _6));

    boost::asio::spawn(*(io), [io, this](boost::asio::yield_context yield) {
        mctpWrapper->detectMctpEndpoints(yield);
        mctpw::MCTPWrapper::EndpointMap eidMap = mctpWrapper->getEndpointMap();
        for (auto& item : eidMap)
        {
            transAddNewDevice(item.first);
        }
    });
    return 0;
}

/**
 * @brief Called by mctpwrapper when device updated.
 *
 * @param  eid          The EID of detected new endpoint.
 * @return true: success, false: failed.
 **/
int spdmTransportMCTP::transRemoveDevice(const mctpw::eid_t eid)
{
    transportEndPoint newEP;
    newEP.devIdentifer = eid;
    return removeDeviceCB == nullptr ? false : removeDeviceCB(&newEP);
}

/**
 * @brief Called by mctpwrapper when device updated.
 *
 * @param  eid          The EID of detected new endpoint.
 * @return true: success, false: failed.
 **/
int spdmTransportMCTP::transAddNewDevice(const mctpw::eid_t eid)
{
    transportEndPoint* pnewEP;
    pnewEP = (transportEndPoint*)malloc(sizeof(transportEndPoint));
    if (pnewEP == NULL)
    {
        return false;
    }
    try
    {
        auto it = mctpWrapper->getEndpointMap().find(eid);
        if (mctpWrapper->getEndpointMap().end() == it)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("spdmTransportMCTP::transAddNewDevice Error add device: " + std::to_string(eid)).c_str());
            free(pnewEP);
            pnewEP = NULL;
            return false;
        }
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("spdmTransportMCTP::transAddNewDevice Adding device: " + std::to_string(eid) + " Service: " + it->second.second).c_str());
    }
    catch (std::exception& e)
    {
        std::string exceptionStr = e.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("spdmTransportMCTP::transAddNewDevice Exception : " + exceptionStr ).c_str());
        return false;
    }
    pnewEP->devIdentifer = eid;
    pnewEP->transType = transType;
    return addNewDeviceCB == nullptr ? false : addNewDeviceCB(pnewEP);
}

/**
 * @brief The async send data function for responder
 *  nonblocking function to send message to remote endpoint.
 *
 * @param  ptransEP          pointer to destination endpoint.
 * @param  requestSize       The size of data to be sent.
 * @param  request           The buffer pointer of data.
 * @param  timeout           The timeout time.
 * @return 0: success, other: failed.
 *
 **/
int spdmTransportMCTP::asyncSendData(transportEndPoint* ptransEP,
                                     uint32_t requestSize, const void* request,
                                     uint64_t timeout)
{
    UNUSED(timeout);
    uint32_t j;
    std::vector<uint8_t> data;

    uint8_t* requestPayload = (uint8_t*)request;
    if (ptransEP == NULL)
        return -1;

    data.push_back(5);

    for (j = 0; j < requestSize; j++)
        data.push_back(*(requestPayload + j));
    mctpw::eid_t eid = ptransEP->devIdentifer;

    boost::asio::spawn(*(pio), [this, eid,
                                data](boost::asio::yield_context yield) {
        mctpWrapper->sendYield(yield, eid,
                               static_cast<uint8_t>(mctpw::MessageType::spdm),
                               false, data);
    });

    return 0;
}

/**
 * @brief The sync send and receive data function for requester
 *  blocking function to send SPDM payload and get response data.
 *
 * @param  ptransEP          pointer to destination endpoint.
 * @param  requestSize       The size of data to be sent.
 * @param  request           The buffer pointer of data.
 * @param  timeout           The timeout time.
 * @param  rspRcvCB          The resRcvCB to be called when response data
 *received.
 * @return 0: success, other: failed.
 *
 **/
int spdmTransportMCTP::syncSendRecvData(transportEndPoint* ptransEP,
                                        uint32_t requestSize,
                                        const void* request, uint64_t timeout,
                                        MsgReceiveCallback rspRcvCB)
{
    uint32_t j;
    std::vector<uint8_t> data;

    uint8_t* requestPayload = (uint8_t*)request;
    if (ptransEP == NULL)
        return -1;
    data.push_back(5); // SPDM mctp ID

    for (j = 0; j < requestSize; j++)
        data.push_back(*(requestPayload + j));
    mctpw::eid_t eid = ptransEP->devIdentifer;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("spdmTransportMCTP::syncSendRecvData eid: " + std::to_string(eid) + ", data size: " + std::to_string(data.size()) + ", timeout: " + std::to_string(timeout)).c_str());
    auto reply = mctpWrapper->sendReceiveBlocked(
        eid, data, std::chrono::milliseconds(500));
    if (reply.first)
    {
        return reply.first.value();
    }
    else
    {
        std::vector<uint8_t> responsePacket = reply.second;
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ("spdmTransportMCTP::syncSendRecvData send recv :response_vector.size():" + std::to_string(responsePacket.size())).c_str());
        std::stringstream ss;
        ss << std::uppercase << std::hex << std::endl;
        for (unsigned int i = 0; i < responsePacket.size(); ++i)
        {
            ss << std::setfill('0') << std::setw(3) << static_cast<uint16_t>(responsePacket[i]);
            if ((i % 32) == 0)
            {
                ss << std::endl;
            }
            else
            {
                ss << ' ';
            }
        }
        ss << std::endl;
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            ss.str().c_str());

        rspRcvCB(ptransEP, responsePacket);

        return 0;
    }
}

} // namespace spdmtransport
