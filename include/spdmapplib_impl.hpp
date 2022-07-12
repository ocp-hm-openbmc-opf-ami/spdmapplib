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

namespace spdmapplib
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
    spdmtransport::TransportEndPoint transEP;
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
class SPDMResponderImpl : public SPDMResponder
{
  public:
    /*APIs called by SPDM daemon*/
    SPDMResponderImpl() = default;
    virtual ~SPDMResponderImpl();
    /**
     * @brief Initial function of SPDM responder.
     *
     * The function will enter daemon mode. Accept request from assigned
     *transport layer.
     *
     * @param  ioc                boost io_context object..
     * @param  trans             The pointer of transport instance.
     * @param  spdmConfig        Application assigned SPDMConfiguration.
     * @return 0: success, other: listed in spdmapplib::errorCodes.
     **/
    int initResponder(std::shared_ptr<boost::asio::io_context> ioc,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      std::shared_ptr<spdmtransport::SPDMTransport> trans,
                      SPDMConfiguration& spdmConfig) override;

    /*APIs called by transport layer*/
    /**
     * @brief Called when new endpoint detected.
     *
     * @param  transEP          The new endpoint object.
     * @return 0: success, other: failed.
     *
     **/
    int addNewDevice(spdmtransport::TransportEndPoint& transEP);

    /**
     * @brief Called when endpoint remove is detected.
     *
     * @param  transEP          The endpoint to be removed.
     * @return 0: success, other: failed.
     *
     **/
    int removeDevice(spdmtransport::TransportEndPoint& transEP);

    /**
     * @brief Called when message received.
     *
     * @param  transEP      The endpoint object to receive data.
     * @param  data          The vector of received data.
     * @return 0: success, other: failed.
     *
     **/

    int addData(spdmtransport::TransportEndPoint& transEP,
                const std::vector<uint8_t>& data);
    /**
     * @brief Called when message received.
     *
     * The function is called in msgRecvCallback to process incoming received
     *data.
     * @return 0: success, other: failed.
     *
     **/
    int processSPDMMessage();

    /**
     * @brief Register to transport layer for handling received data.
     *
     * @param  transEP      The endpoint object to receive data.
     * @param  data          The vector of received data.
     * @return 0: success, other: failed.
     *
     **/
    int msgRecvCallback(spdmtransport::TransportEndPoint& transEP,
                        const std::vector<uint8_t>& data);

    /*Cabllback functions implementation for libspdm */
    /**
     * @brief Register to libspdm for sending SPDM payload.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  request          The request payload data vector.
     * @param  timeout          The timeout time.
     * @return return_status defined in libspdm.
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
     * @return return_status defined in libspdm.
     *
     **/
    return_status deviceReceiveMessage(void* spdmContext,
                                       std::vector<uint8_t>& response,
                                       uint64_t timeout);

    /**
     * @brief Register to libspdm for handling connection state change.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  connectionState  The connection state.
     *
     **/
    void processConnectionState(void* spdmContext,
                                libspdm_connection_state_t connectionState);

    /**
     * @brief Register to libspdm for handling session state change.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  sessionID        The session ID.
     * @param  sessionState     The session state.
     *
     **/
    void processSessionState(void* spdmContext, uint32_t sessionID,
                             libspdm_session_state_t sessionState);
    /*Internal implementation*/
  protected:
    /**
     * @brief Function to setup specific endpoint initial configuration.
     *
     * @param  ItemIndex      The endpoint index.
     * @return 0: success, other: failed.
     *
     **/
    int settingFromConfig(uint8_t ItemIndex);

  private:
    std::shared_ptr<boost::asio::io_context> pioc;

    uint8_t useSlotCount;
    uint8_t curIndex;
    uint32_t useResponderCapabilityFlags;
    uint8_t useMutAuth;
    uint8_t useBasicMutAuth;
    SPDMConfiguration spdmResponderCfg;
    std::vector<spdmItem> spdmPool;
    std::shared_ptr<spdmtransport::SPDMTransport> spdmTrans;
};

/**
 * @brief SPDM requester implementation class
 *
 */
class SPDMRequesterImpl : public SPDMRequester
{
  public:
    SPDMRequesterImpl() = default;
    virtual ~SPDMRequesterImpl();
    /* APIs for requester*/
    /**
     * @brief Initial function of SPDM requester
     *
     * @param  ioc                boost io_context object..
     * @param  trans             The pointer of transport instance.
     * @param  ptransResponder   The pointer to assigned responder EndPoint.
     * @return 0: success, other: listed in spdmapplib::errorCodes.
     **/
    int initRequester(std::shared_ptr<boost::asio::io_context> ioc,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      std::shared_ptr<spdmtransport::SPDMTransport> trans,
                      spdmtransport::TransportEndPoint& transResponder,
                      SPDMConfiguration& spdmConfig) override;
    /**
     * @brief The authentication function
     *
     * @return 0: success, other: failed.
     **/
    int doAuthentication(void) override;
    /**
     * @brief The measurement function
     *
     * @param  sessionid          The session id pointer(reserved for further
     *use).
     *
     * @return 0: success, other: failed.
     **/
    int doMeasurement(const uint32_t* sessionid) override;
    /**
     * @brief Get all measurement function
     *
     * @return vector of all measurements.
     **/
    std::optional<std::vector<uint8_t>> getMeasurements() override;
    /**
     * @brief Get certification function
     *
     * @return vector of certification.
     **/
    std::optional<std::vector<uint8_t>> getCertificate() override;

    /*APIs called by transport layer*/
    /**
     * @brief Set received data to assigned endpoint.
     *
     * @param  transEP          The Endpoint object to receive data.
     * @param  trans             The pointer of transport instance.
     * @return 0: success, other: failed.
     *
     **/
    int addData(spdmtransport::TransportEndPoint& transEP,
                const std::vector<uint8_t>& data);

    /**
     * @brief Function to check if found endpoint is the responder assigned by
     *user.
     *
     * @param  transEP          The endpoint object to be checked.
     * @return 0: success, other: failed.
     *
     **/
    int checkResponderDevice(spdmtransport::TransportEndPoint& transEP);

    /**
     * @brief Function to pass as parameter of syncSendRecvData of transport
     *layer.
     *
     *  The function will be called when send/receive is completed in transport
     *layer.
     * @param  transEP         The endpoint to receive data after send.
     *to.
     * @param  data             The received data buffer.
     * @return 0: success, other: failed.
     *
     **/
    int msgRecvCallback(spdmtransport::TransportEndPoint& transEP,
                        const std::vector<uint8_t>& data);

    /*Callback functions implementation for libspdm*/
    /**
     * @brief Register to libspdm for sending SPDM payload.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  request          The request payload data vector.
     * @param  timeout          The timeout time.
     * @return return_status defined in libspdm.
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
     * @return return_status defined in libspdm.
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
     * @return return_status defined in libspdm.
     *
     **/
    int setupResponder(const spdmtransport::TransportEndPoint& transEP);
    /**
     * @brief Function to setup user assigned endpoint initial configuration.
     *
     * @return 0: success, other: failed.
     *
     **/
    int settingFromConfig(void);

  private:
    bool bResponderFound;
    std::shared_ptr<boost::asio::io_context> pioc;

    uint8_t useSlotCount;
    uint8_t useSlotId;
    uint32_t useRequesterCapabilityFlags;
    uint8_t useMutAuth;
    uint8_t useBasicMutAuth;
    uint16_t mUseReqAsymAlgo;
    uint32_t mUseAsymAlgo;
    uint32_t mUseHashAlgo;
    uint32_t mExeConnection;
    uint8_t mUseMeasurementSummaryHashType;
    uint8_t mUseMeasurementOperation;
    uint8_t mUseMeasurementAttribute;
    SPDMConfiguration spdmRequesterCfg;
    spdmItem spdmResponder; // only one instance for requester.
    spdmtransport::TransportEndPoint transResponder;
    std::shared_ptr<spdmtransport::SPDMTransport> spdmTrans;
};

/*Utility function*/
/**
 * @brief set cert file Path
 *
 * @param certPath : cert file location
 */
void setCertificatePath(std::string& certPath);

} // namespace spdmapplib
