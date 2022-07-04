#pragma once
#include "spdmapplib.hpp"
extern "C"
{
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
}
// for testing
#define EXE_CONNECTION_VERSION_ONLY 0x1
#define EXE_CONNECTION_DIGEST 0x2
#define EXE_CONNECTION_CERT 0x4
#define EXE_CONNECTION_CHAL 0x8
#define EXE_CONNECTION_MEAS 0x10

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

namespace spdmapplib
{
/**
 * @brief SPDM version enum
 *
 */

enum class spdmVersions : uint32_t
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
    spdmtransport::transportEndPoint transEP;
    uint8_t useSlotId;
    uint32_t sessonId;
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
 * @brief SPDM configurations from EntityManager
 *
 */
typedef struct
{
    /* SPDM Version */
    uint32_t version;
    /* library can support requester and responder roles */
    /* Responder configurations */
    uint32_t capability;
    uint32_t hash;
    uint32_t measHash;
    uint32_t asym;
    uint32_t reqasym;
    uint32_t dhe;
    uint32_t aead;

    /* Requester configurations */
    uint32_t transportTimeouts;
} spdmConfiguration;

/**
 * @brief SPDM responder implementation class
 *
 */
class spdmResponderImpl : public spdmResponder
{
  public:
    /*APIs called by SPDM daemon*/
    spdmResponderImpl(){};
    /**
     * @brief Initial function of SPDM responder.
     *
     * The function will enter daemon mode. Accept request from assigned
     *trasport layer.
     *
     * @param  io                boost io_service object..
     * @param  trans             The pointer of transport instance.
     * @return 0: success, other: listed in spdmapplib::errorCodes.
     **/
    int initResponder(
        std::shared_ptr<boost::asio::io_service> io,
        std::shared_ptr<spdmtransport::spdmTransport> trans) override;

    /*APIs called by transport layer*/
    /**
     * @brief Called when new endpoint detected.
     *
     * @param  ptransEP          The pointer to the new endpoint object.
     * @return 0: success, other: failed.
     *
     **/
    int addNewDevice(void* ptransEP);

    /**
     * @brief Called when endpoint remove is detected.
     *
     * @param  ptransEP          The pointer to the removed endpoint object.
     * @return 0: success, other: failed.
     *
     **/
    int removeDevice(void* ptransEP);

    /**
     * @brief Called when message received.
     *
     * @param  ptransEP      The pointer of the endpoint object to receive data.
     * @param  data          The vector of received data.
     * @return 0: success, other: failed.
     *
     **/

    int addData(void* ptransEP, const std::vector<uint8_t>& data);
    /**
     * @brief Called when message received.
     *
     * The function is called in MsgRecvCallback to process incoming receviced
     *data.
     * @return 0: success, other: failed.
     *
     **/
    int processSPDMMessage();

    /**
     * @brief Register to transport layer for handling received data.
     *
     * @param  ptransEP      The pointer of the endpoint object to receive data.
     * @param  data          The vector of received data.
     * @return 0: success, other: failed.
     *
     **/
    int MsgRecvCallback(void* ptransEP, const std::vector<uint8_t>& data);
    /*Cabllback functions implementation for libspdm */
    /**
     * @brief Register to libspdm for sending SPDM payload.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  requestSize      The request payload size.
     * @param  request          The request payload data buffer.
     * @param  timeout          The timeout time.
     * @return return_status defined in libspdm.
     *
     **/
    return_status deviceSendMessage(void* spdmContext, uintn requestSize,
                                    const void* request, uint64_t timeout);

    /**
     * @brief Register to libspdm for receivng SPDM response payload.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  responseSize     The variable pointer for received data size.
     * @param  response         The response data buffer pointer.
     * @param  timeout          The timeout time.
     * @return return_status defined in libspdm.
     *
     **/
    return_status deviceReceiveMessage(void* spdmContext, uintn* responseSize,
                                       void* response, uint64_t timeout);

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
    std::shared_ptr<boost::asio::io_service> pio;

    uint8_t useSlotCount;
    uint8_t curIndex;
    uint32_t useResponderCapabilityFlags;
    uint8_t useMutAuth;
    uint8_t useBasicMutAuth;
    spdmConfiguration spdmResponderCfg;
    std::vector<spdmItem> spdmPool;
    std::shared_ptr<spdmtransport::spdmTransport> spdmTrans;
};

/**
 * @brief SPDM requester implementation class
 *
 */
class spdmRequesterImpl : public spdmRequester
{
  public:
    spdmRequesterImpl(){};
    /* APIs for requester*/
    /**
     * @brief Initial function of SPDM requester
     *
     * @param  io                boost io_service object..
     * @param  trans             The pointer of transport instance.
     * @param  ptransResponder   The pointer to assigned responder EndPoint.
     * @return 0: success, other: listed in spdmapplib::errorCodes.
     **/
    int initRequester(
        std::shared_ptr<boost::asio::io_service> io,
        std::shared_ptr<spdmtransport::spdmTransport> trans,
        spdmtransport::transportEndPoint* ptransResponder) override;
    /**
     * @brief The authentication function
     *
     * @return 0: success, other: failed.
     **/
    int do_authentication(void) override;
    /**
     * @brief The measurement function
     *
     * @param  sessionid          The session id pointer(reserved for futher
     *use).
     *
     * @return 0: success, other: failed.
     **/
    int do_measurement(const uint32_t* sessionid) override;
    /**
     * @brief Get all measurement function
     *
     * @return vector of all measurements.
     **/
    std::optional<std::vector<uint8_t>> get_measurements() override;
    /**
     * @brief Get certification function
     *
     * @return vector of certification.
     **/
    std::optional<std::vector<uint8_t>> get_certificate() override;

    /*APIs called by transport layer*/
    /**
     * @brief Set received data to assigned endpoint.
     *
     * @param  ptransEP          Endpoint object pointer.
     * @param  trans             The pointer of transport instance.
     * @return 0: success, other: failed.
     *
     **/
    int addData(void* ptransEP, const std::vector<uint8_t>& data);

    /**
     * @brief Function to check if found endpoint is the responder assigned by
     *user.
     *
     * @param  ptransEP          Pointer of endpoint object to be checked.
     * @return 0: success, other: failed.
     *
     **/
    int checkResponderDevice(void* ptransEP);

    /**
     * @brief Function to pass as parameter of syncSendRecvData of transport
     *layer.
     *
     *  The function will be called when send/receive is completed in transport
     *layer.
     * @param  ptransEP         Pointer to the endpoint the receviced data send
     *to.
     * @param  data             The receviced data buffer.
     * @return 0: success, other: failed.
     *
     **/
    int MsgRecvCallback(void* ptransEP, const std::vector<uint8_t>& data);

    /*Callback functions implementation for libspdm*/
    /**
     * @brief Register to libspdm for sending SPDM payload.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  requestSize      The request payload size.
     * @param  request          The request payload data buffer.
     * @param  timeout          The timeout time.
     * @return return_status defined in libspdm.
     *
     **/
    return_status deviceSendMessage(void* spdmContext, uintn requestSize,
                                    const void* request, uint64_t timeout);

    /**
     * @brief Register to libspdm for receivng SPDM response payload.
     *
     * @param  spdmContext      The pointer of the spdmcontext.
     * @param  responseSize     The variable pointer for received data size.
     * @param  response         The response data buffer pointer.
     * @param  timeout          The timeout time.
     * @return return_status defined in libspdm.
     *
     **/
    return_status deviceReceiveMessage(void* spdmContext, uintn* responseSize,
                                       void* response, uint64_t timeout);

    /*Internal implementation*/
  protected:
    /**
     * @brief Setup the configuration of user assigned endpoint as target
     *responder.
     *
     * @param  ptransEP          Pointer of endpoint object to be configed.
     * @return return_status defined in libspdm.
     *
     **/
    int setupResponder(spdmtransport::transportEndPoint* ptransEP);
    /**
     * @brief Function to setup user assigned endpoint initial configuration.
     *
     * @return 0: success, other: failed.
     *
     **/
    int settingFromConfig(void);

  private:
    bool bResponderFound;
    std::shared_ptr<boost::asio::io_service> pio;

    uint8_t useSlotCount;
    uint8_t useSlotId;
    uint32_t useRequesterCapabilityFlags;
    uint8_t useMutAuth;
    uint8_t useBasicMutAuth;
    uint16_t m_use_req_asym_algo;
    uint32_t m_use_asym_algo;
    uint32_t m_use_hash_algo;
    uint32_t m_exe_connection;
    uint8_t m_use_measurement_summary_hash_type;
    uint8_t m_use_measurement_operation;
    uint8_t m_use_measurement_attribute;
    spdmConfiguration spdmResponderCfg;
    spdmItem spdmResponder; // only one instance for requester.
    spdmtransport::transportEndPoint transResponder;
    std::shared_ptr<spdmtransport::spdmTransport> spdmTrans;
};

/*Utility functions.*/
using configurationField =
    std::variant<bool, uint64_t, std::string, std::vector<std::string>>;
using configurationMap = std::unordered_map<std::string, configurationField>;

/*
API to get SPDM configuration from Entity Manager. Called by requester and
responder. Consider to move to base class of requester and responder
*/
/**
 * @brief The utility function to get configuration from EntityManager.
 *
 * @param  conn          shared_ptr of sdbusplus::asio::connection.
 * @param  configurationName          Name of
 *configuration("SPDM_responder"/"SPDM_requester").
 * @return spdmConfiguration.
 *
 **/
spdmConfiguration getConfigurationFromEntityManager(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    const std::string& configurationName);
/**
 * @brief Compare given endpoints.
 *
 * @param  pOne          The 1st endpoint te be matched.
 * @param  pTwo          The 2nd endpoint te be matched.
 * @return true: matched, false: different.
 *
 **/
bool matchDevice(spdmtransport::transportEndPoint* pOne,
                 spdmtransport::transportEndPoint* pTwo);
/**
 * @brief Duplicate Endpoint content.
 *
 * @param  pOne          The target endpoint te be copied.
 * @param  pTwo          The source endpoint te be copied.
 * @return true: success, false: failed.
 *
 **/
bool copyDevice(spdmtransport::transportEndPoint* pOne,
                spdmtransport::transportEndPoint* pTwo);

} // namespace spdmapplib
