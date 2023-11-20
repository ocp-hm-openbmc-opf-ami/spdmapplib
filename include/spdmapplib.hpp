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
#include "spdmapplib_errorcodes.hpp"
#include "spdmtransport.hpp"

namespace spdm_app_lib
{
class SPDMRequesterImpl;
class SPDMResponderImpl;
/**
 * @brief SPDM configurations from EntityManager
 *
 */
struct SPDMConfiguration
{
    uint32_t version;
    /* library can support requester and responder roles */
    uint32_t capability;
    uint32_t hash;
    uint32_t measHash;
    uint32_t asym;
    uint32_t reqasym;
    uint32_t dhe;
    uint32_t aead;
    uint32_t slotcount;
    std::string certPath;
};

enum class SPDMConfigIdentifier
{
    version,
    secureVersion,
    requesterCaps,
    responderCaps,
    baseHash,
    measHash,
    asymHash,
    dheValue,
    aeadValue,
    basicMutualSupport,
    mutualAuthValue,
    measSummaryHash,
    measOperation,
    measAttribute
};
std::map<std::string, uint32_t> __attribute__((visibility("default")))
getSPDMConfigMap(SPDMConfigIdentifier configIdentifier);

/**
 * @brief The responder base class
 *
 **/
class SPDMResponder
{
  public:
    SPDMResponder() = delete;
    SPDMResponder(const SPDMResponder&) = delete;
    SPDMResponder& operator=(const SPDMResponder&) = delete;
    SPDMResponder(SPDMResponder&&) = delete;
    SPDMResponder& operator=(SPDMResponder&&) = delete;
    ~SPDMResponder() noexcept;
    /*APIs called by SPDM responder daemon*/
    /**
     * @brief Initial function of SPDM responder
     *  When the function is called, it will enter daemon mode and never return.
     *
     * @param  ioc                boost io_context object.
     * @param  conn              The Pointer to sdbusplus conn.
     * @param  trans             The pointer of transport instance.
     * @param  spdmConfig        Application assigned SPDMConfiguration.
     **/
    SPDMResponder(std::shared_ptr<boost::asio::io_context> ioc,
                  std::shared_ptr<sdbusplus::asio::connection> conn,
                  std::shared_ptr<spdm_transport::SPDMTransport> trans,
                  SPDMConfiguration& spdmConfig);

    bool updateSPDMPool(spdm_transport::TransportEndPoint& endPoint);

  private:
    std::shared_ptr<SPDMResponderImpl> pRespImpl;
};

/**
 * @brief The requester base class
 *
 **/
class SPDMRequester
{
  public:
    /*Requester APIs*/
    SPDMRequester() = delete;
    SPDMRequester(const SPDMRequester&) = delete;
    SPDMRequester& operator=(const SPDMRequester&) = delete;
    SPDMRequester(SPDMRequester&&) = delete;
    SPDMRequester& operator=(SPDMRequester&&) = delete;
    /**
     * @brief Initial function of SPDM requester
     *
     * @param  ioc               The shared_ptr to boost io_context object.
     * @param  conn              The shared_ptr of sdbusplus conn.
     * @param  trans             The pointer of transport instance.
     * @param  endPoint          The pointer to assigned responder EndPoint.
     * @param  spdmConfig        Configuration read from entity-manager.
     *
     **/
    SPDMRequester(std::shared_ptr<boost::asio::io_context> ioc,
                  std::shared_ptr<sdbusplus::asio::connection> conn,
                  std::shared_ptr<spdm_transport::SPDMTransport> trans,
                  spdm_transport::TransportEndPoint& endPoint,
                  SPDMConfiguration& spdmConfig);

    /**
     * @brief Destroy the SPDMRequester object
     *
     */
    ~SPDMRequester() noexcept;
    /**
     * @brief Get all measurement function
     *
     * @param   measurements     The measurements returned for specific endPoint
     * @param   measurementIndex The measurement operation
     * @param   useSlotId        The number of slot for the certificate chain.
     * @return  true             Indicates Success.
     * @return  false            Indicates Failure
     **/
    bool getMeasurements(std::vector<uint8_t>& measurements,
                         uint8_t measurementIndex = 0xff,
                         uint8_t useSlotId = 0);

    /**
     * @brief Get certificate function
     *
     * @param   certificate      The certificate returned for specific endPoint.
     * @param   useSlotId        The number of slot for the certificate chain.
     * @return  true             Indicates Success.
     * @return  false            Indicates Failure
     *
     **/
    bool getCertificate(std::vector<uint8_t>& certificate,
                        uint8_t useSlotId = 0);

  private:
    std::shared_ptr<SPDMRequesterImpl> pReqImpl;
};

} // namespace spdm_app_lib
