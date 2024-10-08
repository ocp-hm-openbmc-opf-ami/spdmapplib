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
     * @brief Get all measurement function
     *
     * @param measurement      vector holding the measurements
     * @param measurementIndex The measurement operation
     * @param useSlotId        The number of slot for the certificate chain.
     * @return true            If, vector contains measurements.
     * @return false           If, vector is empty
     **/
    bool getMeasurements(std::vector<uint8_t>& measurement,
                         uint8_t measurementIndex = 0xff,
                         uint8_t useSlotId = 0);

    /**
     * @brief Get certification function
     *
     * @param certificate     vector holding the certificate
     * @param useSlotId       The number of slot for the certificate chain.
     * @return true           If, vector contains certificate.
     * @return false          If, vector is empty
     **/
    bool getCertificate(std::vector<uint8_t>& certificate,
                        uint8_t useSlotId = 0);

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
     * @brief Send callback registered with libspdm
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  requestSize      The size of request payload.
     * @param  request          The pointer to request.
     * @return LIBSPDM_SUCCESS  when payload is sent successfully
     * @return LIBSPDM_FAILURE  failure when send fails
     */
    static libspdm_return_t requesterDeviceSendMessage(void* spdmContext,
                                                       size_t requestSize,
                                                       const void* request,
                                                       uint64_t timeout);

    /**
     * @brief Receive callback registered with libspdm
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  responseSize     The size of response payload.
     * @param  response         The pointer to response.
     * @return LIBSPDM_SUCCESS  when response is receive successfully
     * @return LIBSPDM_FAILURE  failure when receive fails
     */
    static libspdm_return_t requesterDeviceReceiveMessage(void* spdmContext,
                                                          size_t* responseSize,
                                                          void** response,
                                                          uint64_t timeout);

  private:
    /**
     * @brief Function to get capabilities from SPDM responder
     *
     **/
    bool getCapabilities();

    /**
     * @brief initSpdmContext initiates spdm context
     *
     * @return true
     * @return false
     */
    bool initSpdmContext(void);

    /**
     * @brief isConnStateNegotiated checks for Connection state
     *
     * @return true     if connection State is Negotiated
     * @return false    if connection State is NOT Negotiated
     */
    bool isConnStateNegotiated();

    /**
     * @brief getVCA performs GET_VERSION, GET_CAPS, NEO_ALGO
     *
     * @param onlyVersion   if true, only GET_VERSION is performed
     * @return true         if getVCA is successful
     * @return false        if getVCA fails
     */
    bool getVCA(bool onlyVersion);

    /**
     * @brief The authentication function
     *
     * @param useSlotId       The number of slot for the certificate chain.
     * @return true           If, doAuth passes.
     * @return false          If, doAuth fails
     **/
    bool doAuthentication(uint8_t useSlotId = 0);

    /**
     * @brief The measurement function
     *
     * @param  sessionid      The session id pointer
     * @param useSlotId       The number of slot for the certificate chain.
     * @return true           If, doMeas succeeds
     * @return false          If, doMeas fails
     **/
    bool doMeasurement(const uint32_t* sessionid, uint8_t useSlotId = 0);

    /**
     * @brief sets up the SPDM Requester
     *
     * @return true           success
     * @return false          failure
     */
    bool setupSpdmRequester();

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

    std::shared_ptr<boost::asio::io_context> ioc;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    uint8_t mUseMeasurementOperation = 0xff;
    uint32_t capability = 0;
    std::shared_ptr<spdm_transport::SPDMTransport> spdmTrans;
    spdmItem spdmResponder{}; // only one instance for requester.
    spdm_transport::TransportEndPoint responderEndpoint{};
    SPDMConfiguration spdmRequesterCfg{};
};

} // namespace spdm_app_lib
