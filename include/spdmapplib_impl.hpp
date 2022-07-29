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
// clang-format off
extern "C"
{
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "library/malloclib.h"
}
// clang-format on

inline constexpr uint32_t exeConnectionVersionOnly = 0x1;
inline constexpr uint32_t exeConnectionDigest = 0x2;
inline constexpr uint32_t exeConnectionCert = 0x4;
inline constexpr uint32_t exeConnectionChal = 0x8;
inline constexpr uint32_t exeConnectionMeas = 0x10;

namespace spdm_app_lib
{
/**
 * @brief SPDM version enum
 *
 */

enum class SPDMVersions : uint32_t
{
    spdmv1p1 = 0x01
};

enum class SPDMDeviceEvent : uint8_t
{
    deviceAdded = 0x01,
    deviceRemoved
};

/**
 * @brief SPDM device context structure
 *
 */
typedef struct
{
    void* pspdmContext;
    spdm_transport::TransportEndPoint transEP;
    uint8_t useSlotId;
    uint32_t sessionId;
    uint32_t useVersion;
    uint16_t useReqAsymAlgo;
    uint32_t useMeasurementHashAlgo;
    uint32_t useAsymAlgo;
    uint32_t useHashAlgo;
    libspdm_connection_state_t connectStatus;
    std::vector<uint8_t> data;
    std::vector<uint8_t> dataCert;
    std::vector<uint8_t> dataMeas;
} spdmItem;

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
    uint8_t useSlotCount = 0;
    uint8_t curIndex = 0;
    uint32_t useResponderCapabilityFlags = 0;
    uint8_t useMutAuth = 0;
    uint8_t useBasicMutAuth = 0;
    std::shared_ptr<spdm_transport::SPDMTransport> spdmTrans;
    SPDMConfiguration spdmResponderCfg{};
    std::vector<spdmItem> spdmPool{};
};

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
                      spdm_transport::TransportEndPoint& transResponder,
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
     * @return return_status    defined in libspdm.
     *
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
     *
     **/
    return_status deviceReceiveMessage(void* spdmContext,
                                       std::vector<uint8_t>& response,
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

  private:
    std::shared_ptr<boost::asio::io_context> ioc;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    uint8_t useSlotCount = 0;
    uint8_t useSlotId = 0;
    uint32_t useRequesterCapabilityFlags = 0;
    uint8_t useMutAuth = 0;
    uint8_t useBasicMutAuth = 0;
    uint16_t mUseReqAsymAlgo = 0;
    uint32_t mUseAsymAlgo = 0;
    uint32_t mUseHashAlgo = 0;
    uint32_t mExeConnection = 0;
    uint8_t mUseMeasurementSummaryHashType = 0;
    uint8_t mUseMeasurementOperation = 0;
    uint8_t mUseMeasurementAttribute = 0;
    std::shared_ptr<spdm_transport::SPDMTransport> spdmTrans;
    spdmItem spdmResponder{}; // only one instance for requester.
    spdm_transport::TransportEndPoint transResponder{};
    SPDMConfiguration spdmRequesterCfg{};
};

/*Utility function*/
/**
 * @brief set cert file Path
 *
 * @param certPath : cert file location
 */
void setCertificatePath(std::string& certPath);

} // namespace spdm_app_lib
