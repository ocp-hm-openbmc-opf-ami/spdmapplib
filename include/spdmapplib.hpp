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

/**
 * @brief The responder base class
 *
 **/
class SPDMResponder
{
  public:
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
     * @return 0: success, other: listed in spdmapplib::errorCodes.
     **/
    SPDMResponder(std::shared_ptr<boost::asio::io_context> ioc,
                  std::shared_ptr<sdbusplus::asio::connection> conn,
                  std::shared_ptr<spdmtransport::SPDMTransport> trans,
                  SPDMConfiguration& pSpdmConfig);

    int removeDevice(spdmtransport::TransportEndPoint& endPoint);

  private:
    std::shared_ptr<SPDMResponderImpl> pRespimpl;
};

/**
 * @brief The requester base class
 *
 **/
class SPDMRequester
{
  public:
    /*Requester APIs*/
    /**
     * @brief Initial function of SPDM requester
     *
     * @param  ioc               The shared_ptr to boost io_context object.
     * @param  conn              The shared_ptr of sdbusplus conn.
     * @param  trans             The pointer of transport instance.
     * @param  ptransResponder   The pointer to assigned responder EndPoint.
     * @param  pSpdmConfig       The SPDM configuration read from
     *entity-manager.
     *
     **/
    SPDMRequester(std::shared_ptr<boost::asio::io_context> ioc,
                  std::shared_ptr<sdbusplus::asio::connection> conn,
                  std::shared_ptr<spdmtransport::SPDMTransport> trans,
                  spdmtransport::TransportEndPoint& endPoint,
                  SPDMConfiguration& pSpdmConfig);

    /**
     * @brief Destroy the SPDMRequester object
     *
     */
    ~SPDMRequester() noexcept;
    /**
     * @brief Get all measurement function
     *
     * @param   measurements     The certificate returned for specific endPoint
     * @return  bool             Indicating success or failure of the operation.
     * @return  True             Indicates Success and False indicate Failure.
     *
     **/
    bool getMeasurements(std::vector<uint8_t>& certificate);

    /**
     * @brief Get certificate function
     *
     * @param   measurements     The certificate returned for specific endPoint.
     * @return  bool             Indicating success or failure of the operation.
     * @return  True             Indicates Success and False indicate Failure.
     *
     **/
    bool getCertificate(std::vector<uint8_t>& measurements);

  private:
    std::shared_ptr<SPDMRequesterImpl> pReqimpl;
};

} // namespace spdmapplib
