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
#include "spdmapplib.hpp"
#include "spdmapplib_common.hpp"

namespace spdm_app_lib
{
/**
 * @brief SPDM responder implementation class
 *
 */
class SPDMResponderImpl
{
  public:
    /*APIs called by SPDM daemon*/
    SPDMResponderImpl() = delete;
    SPDMResponderImpl(const SPDMResponderImpl&) = delete;
    SPDMResponderImpl& operator=(const SPDMResponderImpl&) = delete;
    SPDMResponderImpl(SPDMResponderImpl&&) = delete;
    SPDMResponderImpl& operator=(SPDMResponderImpl&&) = delete;
    ~SPDMResponderImpl();
    /**
     * @brief Constructor of SPDM responder.
     *
     * @param  ioc               boost io_context object.
     * @param  conn              sdbusplus conn
     * @param  trans             The pointer of transport instance.
     * @param  spdmConfig        Application assigned SPDMConfiguration.
     **/
    SPDMResponderImpl(std::shared_ptr<boost::asio::io_context> ioc,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      std::shared_ptr<spdm_transport::SPDMTransport> trans,
                      SPDMConfiguration& spdmConfig);

    /**
     * @brief Called when endpoint remove is detected.
     *
     * @param  transEP          The endpoint to be removed.
     * @return true             If, updating spdm pool is successful
     * @return false            If, updating pool failed
     **/
    bool updateSPDMPool(spdm_transport::TransportEndPoint& transEP);

    /**
     * @brief Register to libspdm for sending SPDM payload.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  request          The request payload data vector.
     * @param  timeout          The timeout time.
     * @return true             when payload is sent successfully
     * @return false            failure in sending payload
     **/
    bool deviceSendMessage(void* spdmContext,
                           const std::vector<uint8_t>& request,
                           uint64_t timeout);

    /**
     * @brief Register to libspdm for receiving SPDM response payload.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  response         The response data buffer vector.
     * @param  timeout          The timeout time.
     * @return true             when payload is received successfully
     * @return false            failure in receiving payload
     **/
    bool deviceReceiveMessage(void* spdmContext, std::vector<uint8_t>& response,
                              uint64_t timeout);

    /**
     * @brief Register to libspdm for handling connection state change.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  connectionState  The connection state.
     **/
    void processConnectionState(void* spdmContext,
                                libspdm_connection_state_t connectionState);

    /**
     * @brief Register to libspdm for handling session state change.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  sessionID        The session ID.
     * @param  sessionState     The session state.
     **/
    void processSessionState(void* spdmContext, uint32_t sessionID,
                             libspdm_session_state_t sessionState);

  private:
    /**
     * @brief initSpdmContext initiates spdm context
     *
     * @return true
     * @return false
     */
    bool initSpdmContext(void);

    /**
     * @brief Called when new endpoint detected.
     *
     * @param  transEP          The new endpoint object.
     * @return true             If adding device is successful.
     * @return false            If adding device failed.
     **/
    bool addNewDevice(spdm_transport::TransportEndPoint& transEP);

    /**
     * @brief Called when message received.
     *
     * @param  transEP      The endpoint object sending data.
     * @param  data         The vector of received data.
     * @return true         If, adding data is successful
     * @return false        If, adding data is failed
     **/
    bool addData(spdm_transport::TransportEndPoint& transEP,
                 const std::vector<uint8_t>& data);

    /**
     * @brief Called when message received.
     *
     * The function is called in msgRecvCallback to process incoming received
     *data.
     * @param  transEP      The endpoint object sending data.
     * @return true         If, processing SPDM msg is successful.
     * @return false        If, processing SPDM msg failed
     **/
    bool processSPDMMessage(spdm_transport::TransportEndPoint& transEP);

    /**
     * @brief Register to transport layer for handling received data.
     *
     * @param  transEP      The endpoint object to receive data.
     * @param  data         The vector of received data.
     * @return true         If, msg call back invoked successfully.
     * @return false        If, invoking msg callback fails
     **/
    bool msgRecvCallback(spdm_transport::TransportEndPoint& transEP,
                         const std::vector<uint8_t>& data);

    std::shared_ptr<boost::asio::io_context> ioc;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::shared_ptr<spdm_transport::SPDMTransport> spdmTrans;
    SPDMConfiguration spdmResponderCfg{};
    std::vector<spdmItem> spdmPool{};
};

} // namespace spdm_app_lib
