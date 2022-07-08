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
#include "spdmtransport.hpp"

namespace spdmapplib
{
/**
 * @brief spdmapplib error codes list.
 *
 */
enum class errorCodes : int
{
    spdmConfigurationNotFoundInEntityManager =
        1,                 // SPDM configuration not found in EntityManager.
    libspdmReturnError = 2 // libspdm function calls return error.
};

/**
 * @brief SPDM configurations from EntityManager
 *
 */
typedef struct
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
    char* certPath;
} spdmConfiguration;

/**
 * @brief The responder base class
 *
 **/
class spdmResponder
{
  public:
    virtual ~spdmResponder() = default;
    /*APIs called by SPDM responder daemon*/
    /**
     * @brief Initial function of SPDM responder
     *  When the function is called, it will enter daemon mode and never return.
     *
     * @param  io                boost io_service object..
     * @param  trans             The pointer of transport instance.
     * @return 0: success, other: listed in spdmapplib::errorCodes.
     **/
    virtual int
        initResponder(std::shared_ptr<boost::asio::io_service> io,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      std::shared_ptr<spdmtransport::spdmTransport> trans,
                      spdmConfiguration* pSpdmConfig) = 0;
};

/**
 * @brief The requester base class
 *
 **/
class spdmRequester
{
  public:
    virtual ~spdmRequester() = default;
    /*Requester APIs*/
    /**
     * @brief Initial function of SPDM requester
     *
     * @param  io                boost io_service object..
     * @param  trans             The pointer of transport instance.
     * @param  ptransResponder   The pointer to assigned responder EndPoint.
     * @return 0: success, other: listed in spdmapplib::errorCodes.
     *
     **/
    virtual int
        initRequester(std::shared_ptr<boost::asio::io_service> io,
                      std::shared_ptr<sdbusplus::asio::connection> conn,
                      std::shared_ptr<spdmtransport::spdmTransport> trans,
                      spdmtransport::transportEndPoint* ptransResponder,
                      spdmConfiguration* pSpdmConfig) = 0;
    /**
     * @brief The authentication function
     *
     * @return 0: success, other: failed.
     **/
    virtual int do_authentication(void) = 0;
    /**
     * @brief The measurement function
     *
     * @param  sessionid          The session id pointer(reserved for further
     *use).
     * @return 0: success, other: failed.
     *
     **/
    virtual int do_measurement(const uint32_t* sessionid) = 0;
    /**
     * @brief Get all measurement function
     * @return vector of all measurements.
     *
     **/
    virtual std::optional<std::vector<uint8_t>> get_measurements() = 0;
    /**
     * @brief Get certification function
     * @return vector of certification.
     *
     **/
    virtual std::optional<std::vector<uint8_t>> get_certificate() = 0;
};

/**
 * @brief Requester object create Factory function.
 *
 * @return Pointer to Requester implementation object.
 *
 **/
std::shared_ptr<spdmRequester> createRequester();

/**
 * @brief Responder object create Factory function.
 *
 * @return Pointer to Responder implementation object.
 *
 **/
std::shared_ptr<spdmResponder> createResponder();

} // namespace spdmapplib
