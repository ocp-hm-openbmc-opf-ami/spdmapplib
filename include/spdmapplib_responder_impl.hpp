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
#include "spdmapplib.hpp"
#include "spdmapplib_impl.hpp"

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

    /*APIs called by transport layer*/
    /**
     * @brief Called when new endpoint detected.
     *
     * @param  transEP          The new endpoint object.
     * @return true             If adding device is successful.
     * @return false            If adding device failed.
     **/
    bool addNewDevice(spdm_transport::TransportEndPoint& transEP);

    /**
     * @brief Called when endpoint remove is detected.
     *
     * @param  transEP          The endpoint to be removed.
     * @return true             If, updating spdm pool is successful
     * @return false            If, updating pool failed
     **/
    bool updateSPDMPool(spdm_transport::TransportEndPoint& transEP);

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

    /*Cabllback functions implementation for libspdm */
    /**
     * @brief Register to libspdm for sending SPDM payload.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  request          The request payload data vector.
     * @param  timeout          The timeout time.
     * @return return_status    defined in libspdm.
     **/
    return_status deviceSendMessage(void* spdmContext,
                                    const std::vector<uint8_t>& request,
                                    uint64_t timeout);

    /**
     * @brief Register to libspdm for receiving SPDM response payload.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  response         The response data buffer vector.
     * @param  timeout          The timeout time.
     * @return return_status    defined in libspdm.
     **/
    return_status deviceReceiveMessage(void* spdmContext,
                                       std::vector<uint8_t>& response,
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
    /*Internal implementation*/
  protected:
    /**
     * @brief Function to setup specific endpoint initial configuration.
     *
     * @param  ItemIndex      The endpoint index.
     * @return true           If getting config is success.
     * @return false          If,getting config fails.
     **/
    bool settingFromConfig(uint8_t ItemIndex);

  private:
    std::shared_ptr<boost::asio::io_context> ioc;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    uint8_t curIndex = 0;
    std::shared_ptr<spdm_transport::SPDMTransport> spdmTrans;
    SPDMConfiguration spdmResponderCfg{};
    std::vector<spdmItem> spdmPool{};
};

} // namespace spdm_app_lib