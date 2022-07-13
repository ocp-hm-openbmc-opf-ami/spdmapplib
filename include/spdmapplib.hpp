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
#include "spdmapplib_errorcodes.hpp"
#include "spdmtransport.hpp"

namespace spdmapplib
{
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

/**
 * @brief The responder base class
 *
 **/
class SPDMResponder
{
  public:
    virtual ~SPDMResponder() = default;
    /*APIs called by SPDM responder daemon*/
    /**
     * @brief Initial function of SPDM responder
     *  When the function is called, it will enter daemon mode and never return.
     *
     * @param  ioc                boost io_context object..
     * @param  trans             The pointer of transport instance.
     * @param  spdmConfig        Application assigned SPDMConfiguration.
     * @return 0: success, other: listed in spdmapplib::errorCodes.
     **/
    virtual int
        initResponder(std::shared_ptr<boost::asio::io_context> ioc,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      std::shared_ptr<spdmtransport::SPDMTransport> trans,
                      SPDMConfiguration& spdmConfig) = 0;
};

/**
 * @brief The requester base class
 *
 **/
class SPDMRequester
{
  public:
    virtual ~SPDMRequester() = default;
    /*Requester APIs*/
    /**
     * @brief Initial function of SPDM requester
     *
     * @param  ioc               The shared_ptr to boost io_context object..
     * @param  trans             The pointer of transport instance.
     * @param  ptransResponder   The pointer to assigned responder EndPoint.
     * @return 0: success, other: listed in spdmapplib::errorCodes.
     *
     **/
    virtual int
        initRequester(std::shared_ptr<boost::asio::io_context> ioc,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      std::shared_ptr<spdmtransport::SPDMTransport> trans,
                      spdmtransport::TransportEndPoint& transResponder,
                      SPDMConfiguration& pSpdmConfig) = 0;
    /**
     * @brief The authentication function
     *
     * @return 0: success, other: failed.
     **/
    virtual int doAuthentication(void) = 0;
    /**
     * @brief The measurement function
     *
     * @param  sessionid          The session id pointer(reserved for further
     *use).
     * @return 0: success, other: failed.
     *
     **/
    virtual int doMeasurement(const uint32_t* sessionid) = 0;
    /**
     * @brief Get all measurement function
     * @return vector of all measurements.
     *
     **/
    virtual std::optional<std::vector<uint8_t>> getMeasurements() = 0;
    /**
     * @brief Get certification function
     * @return vector of certification.
     *
     **/
    virtual std::optional<std::vector<uint8_t>> getCertificate() = 0;
};

/**
 * @brief Requester object create Factory function.
 *
 * @return Pointer to Requester implementation object.
 *
 **/
std::shared_ptr<SPDMRequester> createRequester();

/**
 * @brief Responder object create Factory function.
 *
 * @return Pointer to Responder implementation object.
 *
 **/
std::shared_ptr<SPDMResponder> createResponder();

} // namespace spdmapplib
