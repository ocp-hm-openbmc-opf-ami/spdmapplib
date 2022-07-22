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
#include "spdmapplib_errorcodes.hpp"
#include "spdmtransport.hpp"

namespace spdm_transport
{
/**
 * @brief SPDM transport layer implemented using MCTP
 *
 **/

class SPDMTransportMCTP : public SPDMTransport
{
  public:
    /*APIs called by spdmAppLib layer*/
    /**
     * @brief SPDMTransportMCTP constructor
     * @param  ioc               shared_ptr to boost io_context object.
     * @param  conn              shared_ptr to already existing boost
     * @param  id        Transport layer interface id(here only for MCTPoverPCIe
     *or MCTPoverSMBus).
     *
     **/
    SPDMTransportMCTP(std::shared_ptr<boost::asio::io_service> pio,
                      std::shared_ptr<sdbusplus::asio::connection> pconn,
                      mctpw::BindingType tranType);

    /**
     * @brief Initial function of transport instance
     *

     *asio::connection.
     * @param  msgRcvCB          The callback function for messages received(for
     *responder used).
     **/
    void setListener(MsgReceiveCallback msgRcvCB) override;

    /**
     * @brief The async send data function for responder
     *  nonblocking function to send message to remote endpoint.
     *
     * @param  transEP           The destination endpoint.
     * @param  request           The buffer vector of data.
     * @param  timeout           The timeout time.
     * @return 0: success, other: failed.
     *
     **/
    int asyncSendData(TransportEndPoint& transEP,
                      const std::vector<uint8_t>& request,
                      uint64_t timeout) override;

    /**
     * @brief The sync send and receive data function for requester
     *  blocking function to send SPDM payload and get response data.
     *
     * @param transEP     The destination endpoint.
     * @param request     The vector of data payload.
     * @param timeout     The timeout time.
     * @param rspRcvCB    The resRcvCB to be called when response data received.
     * @return 0: success, other: failed.
     *
     **/
    int sendRecvData(TransportEndPoint& transEP,
                     const std::vector<uint8_t>& request, uint64_t timeout,
                     std::vector<uint8_t>& response) override;

    /**
     * @brief The function is responsible for doing discovery of the endPoints.
     * @param  callback
     *
     **/
    void initDiscovery(
        std::function<void(boost::asio::yield_context yield,
                           spdm_transport::TransportEndPoint endPoint,
                           spdm_transport::Event event)>
            onEndPointChange) override;

    /*APIs called by mctpwrapper callback function*/
  private:
    /**
     * @brief Called by mctpwrapper when device updated.
     *
     * @param eid  The EID of detected new endpoint.
     **/
    void transAddNewDevice(const mctpw::eid_t eid);
    /**
     * @brief Called by mctpwrapper when device updated.
     *
     * @param eid The EID of detected removed endpoint.
     **/
    void transRemoveDevice(const mctpw::eid_t eid);

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
    OnDeviceCallback onDeviceUpdtCB = nullptr;
    MsgReceiveCallback msgReceiveCB = nullptr;

  protected:
    std::shared_ptr<boost::asio::io_context> ioc;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    mctpw::BindingType transType; /*MCTP over PCIe, MCTP over SMBus*/
    std::shared_ptr<mctpw::MCTPWrapper> mctpWrapper;
};
} // namespace spdm_transport
