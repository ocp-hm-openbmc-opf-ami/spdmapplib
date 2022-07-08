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
#include "mctp_wrapper.hpp"
#include "spdmtransport.hpp"

#define UNUSED(x) (void)(x)
namespace spdmtransport
{
/**
 * @brief SPDM transport layer implemented using MCTP
 *
 **/

class spdmTransportMCTP : public spdmTransport
{
  public:
    /*APIs called by spdmAppLib layer*/
    /**
     * @brief spdmTransportMCTP constructor
     *
     * @param  id        Transport layer interface id(here only for MCTPoverPCIe
     *or MCTPoverSMBus).
     *
     **/
    spdmTransportMCTP(TransportIdentifier id)
    {
        transType = id;
    };

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
    int initTransport(std::shared_ptr<boost::asio::io_service> io,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      AddRemoveDeviceCallback addCB,
                      AddRemoveDeviceCallback delCB,
                      MsgReceiveCallback msgRcvCB = nullptr) override;

    /**
     * @brief Get the interface type of transport layer
     * @return TransportIdentifier
     *
     **/
    TransportIdentifier getTransType(void) override
    {
        return transType;
    };

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
    int asyncSendData(transportEndPoint* ptransEP, uint32_t requestSize,
                      const void* request, uint64_t timeout) override;

    /**
     * @brief The sync send and receive data function for requester
     *  blocking function to send SPDM payload and get response data.
     *
     * @param ptransEP    pointer to destination endpoint.
     * @param requestSize The size of data to be sent.
     * @param request     The buffer pointer of data.
     * @param timeout     The timeout time.
     * @param rspRcvCB    The resRcvCB to be called when response data received.
     * @return 0: success, other: failed.
     *
     **/
    int syncSendRecvData(transportEndPoint* ptransEP, uint32_t requestSize,
                         const void* request, uint64_t timeout,
                         MsgReceiveCallback rspRcvCB) override;

    /*APIs called by mctpwrapper callback function*/
  private:
    /**
     * @brief Called by mctpwrapper when device updated.
     *
     * @param eid  The EID of detected new endpoint.
     **/
    int transAddNewDevice(const mctpw::eid_t eid);
    /**
     * @brief Called by mctpwrapper when device updated.
     *
     * @param eid The EID of detected removed endpoint.
     **/
    int transRemoveDevice(const mctpw::eid_t eid);

    /**
     * @brief Function registered to mctpwrapper as receiving message Callback.
     *
     **/
    void transMsgRecvCallback(void*, mctpw::eid_t srcEid, bool tagOwner,
                              uint8_t msgTag, const std::vector<uint8_t>& data,
                              int);

    /**
     * @brief Function registered to mctpwrapper as device update handler.
     *
     **/
    void transOnDeviceUpdate(void*, const mctpw::Event& evt,
                             boost::asio::yield_context yield);

    /* Callback function pointers */
    AddRemoveDeviceCallback addNewDeviceCB = nullptr;
    AddRemoveDeviceCallback removeDeviceCB = nullptr;
    MsgReceiveCallback msgReceiveCB = nullptr;

  protected:
    TransportIdentifier transType; /*MCTP over PCIe, MCTP over SMBus, SDSi*/
    std::shared_ptr<boost::asio::io_service> pio;
    std::shared_ptr<sdbusplus::asio::connection> pconn;
    std::shared_ptr<mctpw::MCTPWrapper> mctpWrapper;
};
} // namespace spdmtransport
