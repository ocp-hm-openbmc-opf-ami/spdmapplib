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
#include "spdmapplib_common.hpp"

namespace spdm_app_lib
{
/**
 * @brief SPDM requester implementation class
 *
 */
class SPDMRequesterImpl
{
  public:
    /* APIs for requester*/
    SPDMRequesterImpl() = delete;
    SPDMRequesterImpl(const SPDMRequesterImpl&) = delete;
    SPDMRequesterImpl& operator=(const SPDMRequesterImpl&) = delete;
    SPDMRequesterImpl(SPDMRequesterImpl&&) = delete;
    SPDMRequesterImpl& operator=(SPDMRequesterImpl&&) = delete;
    ~SPDMRequesterImpl();
    /**
     * @brief Initial function of SPDM requester
     *
     * @param  ioc                boost io_context object.
     * @param  trans             The pointer of transport instance.
     * @param  ptransResponder   The pointer to assigned responder EndPoint.
     **/
    SPDMRequesterImpl(std::shared_ptr<boost::asio::io_context> ioc,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      std::shared_ptr<spdm_transport::SPDMTransport> trans,
                      spdm_transport::TransportEndPoint& endPoint,
                      SPDMConfiguration& spdmConfig);

    /**
     * @brief The authentication function
     *
     * @return true           If, doAuth passes.
     * @return false          If, doAuth fails
     **/
    bool doAuthentication(void);
    /**
     * @brief The measurement function
     *
     * @param  sessionid      The session id pointer
     * @return true           If, doMeas succeeds
     * @return false          If, doMeas fails
     **/
    bool doMeasurement(const uint32_t* sessionid);
    /**
     * @brief Get all measurement function
     *
     * @param measurement     vector holding the measurements
     * @return true           If, vector contains measurements.
     * @return false          If, vector is empty
     **/
    bool getMeasurements(std::vector<uint8_t>& measurement);
    /**
     * @brief Get certification function
     *
     * @param certificate     vector holding the certificate
     * @return true           If, vector contains certificate.
     * @return false          If, vector is empty
     **/
    bool getCertificate(std::vector<uint8_t>& certificate);
    /*APIs called by transport layer*/
    /**
     * @brief Set received data to assigned endpoint.
     *
     * @param  transEP        The Endpoint object to receive data.
     * @param  trans          The pointer of transport instance.
     * @return true           If, add Data is successful.
     * @return false          If, add Data fails
     **/
    void addData(spdm_transport::TransportEndPoint& transEP,
                 const std::vector<uint8_t>& data);

    /**
     * @brief Function to receive async data from transport
     *
     * @param  transEP    The endpoint information.
     * @param  data       The received data buffer.
     **/
    void msgRecvCallback(spdm_transport::TransportEndPoint& transEP,
                         const std::vector<uint8_t>& data);

    /*Callback functions implementation for libspdm*/
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

    /*Internal implementation*/
  protected:
    /**
     * @brief Setup the configuration of user assigned endpoint as target
     *responder.
     *
     * @param  transEP        The endpoint object to be configured.
     * @return true           If, setupResponder is successful.
     * @return false          If, setupResponder fails
     **/
    bool setupResponder(const spdm_transport::TransportEndPoint& transEP);
    /**
     * @brief Function to setup user assigned endpoint initial configuration.
     * @return true           If getting config is success.
     * @return false          If,getting config fails.
     **/
    bool settingFromConfig(void);
    /** @brief isConnStateNegotiated checks for Connection state
     *
     * @return true     if connection State is Negotiated
     * @return false    if connection State is NOT Negotiated
     **/
    bool isConnStateNegotiated();
    /**
     * @brief getVCA performs GET_VERSION, GET_CAPS, NEO_ALGO
     *
     * @param onlyVersion   if true, only GET_VERSION is performed
     * @return true         if getVCA is successful
     * @return false        if getVCA fails
     */
    bool getVCA(bool onlyVersion);

  private:
    std::shared_ptr<boost::asio::io_context> ioc;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    uint8_t mUseMeasurementOperation = 0;
    std::shared_ptr<spdm_transport::SPDMTransport> spdmTrans;
    spdmItem spdmResponder{}; // only one instance for requester.
    spdm_transport::TransportEndPoint transResponder{};
    SPDMConfiguration spdmRequesterCfg{};
};

} // namespace spdm_app_lib