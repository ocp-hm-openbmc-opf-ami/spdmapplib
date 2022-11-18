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
    SPDMTransportMCTP() = delete;
    SPDMTransportMCTP(const SPDMTransportMCTP&) = delete;
    SPDMTransportMCTP& operator=(const SPDMTransportMCTP&) = delete;
    SPDMTransportMCTP(SPDMTransportMCTP&&) = delete;
    SPDMTransportMCTP& operator=(SPDMTransportMCTP&&) = delete;
    /*APIs called by spdmAppLib layer*/
    /**
     * @brief SPDMTransportMCTP constructor
     * @param  ioc       shared_ptr to boost io_context object.
     * @param  conn      shared_ptr to already existing boost
     * @param  id        Transport layer interface id.
     **/
    SPDMTransportMCTP(std::shared_ptr<boost::asio::io_service> io,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      mctpw::BindingType tranType);

    /**
     * @brief Initial function of transport instance
     * @param  msgRcvCB  The callback function for messages received.
     **/
    void setListener(MsgReceiveCallback msgRcvCB) override;

    /**
     * @brief The async send data function for responder
     *  nonblocking function to send message to remote endpoint.
     * @param  transEP           The destination endpoint.
     * @param  request           The buffer vector of data.
     * @param  timeout           The timeout time.
     * @return 0                 Send is successful
     * @return other values      Send failed
     **/
    int asyncSendData(TransportEndPoint& transEP,
                      const std::vector<uint8_t>& request,
                      uint64_t timeout) override;

    /**
     * @brief The sync send and receive data function for requester
     *  blocking function to send SPDM payload and get response data.
     * @param transEP     The destination endpoint.
     * @param request     The vector of data payload.
     * @param timeout     The timeout time.
     * @param rspRcvCB    The resRcvCB to be called when response data received.
     * @return 0                 Send is successful
     * @return other values      Send failed
     **/
    int sendRecvData(TransportEndPoint& transEP,
                     const std::vector<uint8_t>& request, uint64_t timeout,
                     std::vector<uint8_t>& response) override;

    /**
     * @brief The function is responsible for doing discovery of the endPoints.
     * @param  callback
     **/
    void initDiscovery(
        std::function<void(spdm_transport::TransportEndPoint endPoint,
                           spdm_transport::Event event)>
            onEndPointChange) override;

    /**
     * @brief Defines the current underlying transport
     *
     * @return std::string   returns the transport as MCTP
     */
    std::string getSPDMtransport() override;
    /*APIs called by mctpwrapper callback function*/
  private:
    /**
     * @brief Called by mctpwrapper when device updated.
     * @param eid  The EID of detected new endpoint.
     **/
    void transAddNewDevice(const mctpw::eid_t eid);
    /**
     * @brief Called by mctpwrapper when device updated.
     * @param eid The EID of detected removed endpoint.
     **/
    void transRemoveDevice(const mctpw::eid_t eid);

    /**
     * @brief Function registered to mctpwrapper as receiving message Callback.
     **/
    void transMsgRecvCallback(void*, mctpw::eid_t srcEid, bool tagOwner,
                              uint8_t msgTag, const std::vector<uint8_t>& data,
                              int);

    /**
     * @brief Function registered to mctpwrapper as device update handler.
     **/
    void transOnDeviceUpdate(void*, const mctpw::Event& evt,
                             boost::asio::yield_context yield);

    OnDeviceCallback onDeviceUpdtCB = nullptr;
    MsgReceiveCallback msgReceiveCB = nullptr;
    std::shared_ptr<boost::asio::io_context> ioc;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    mctpw::BindingType transType; /*MCTP over PCIe, MCTP over SMBus*/
    std::shared_ptr<mctpw::MCTPWrapper> mctpWrapper;
};
} // namespace spdm_transport
