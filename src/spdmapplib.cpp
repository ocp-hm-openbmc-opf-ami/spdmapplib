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

#include "spdmapplib.hpp"

#include "spdmapplib_impl.hpp"
#include "spdmapplib_requester_impl.hpp"
#include "spdmapplib_responder_impl.hpp"
#include "spdmtransport.hpp"

namespace spdm_app_lib
{
SPDMRequester::SPDMRequester(
    std::shared_ptr<boost::asio::io_context> ioc,
    std::shared_ptr<sdbusplus::asio::connection> conn,
    std::shared_ptr<spdm_transport::SPDMTransport> trans,
    spdm_transport::TransportEndPoint& transResponder,
    SPDMConfiguration& pSpdmConfig) :
    pReqImpl(std::make_shared<SPDMRequesterImpl>(ioc, conn, trans,
                                                 transResponder, pSpdmConfig))
{}

bool SPDMRequester::getCertificate(std::vector<uint8_t>& certificate)
{
    return pReqImpl->getCertificate(certificate);
}

bool SPDMRequester::getMeasurements(std::vector<uint8_t>& measurements)
{
    return pReqImpl->getMeasurements(measurements);
}

SPDMRequester::~SPDMRequester() noexcept = default;

SPDMResponder::SPDMResponder(
    std::shared_ptr<boost::asio::io_context> ioc,
    std::shared_ptr<sdbusplus::asio::connection> conn,
    std::shared_ptr<spdm_transport::SPDMTransport> trans,
    SPDMConfiguration& pSpdmConfig) :
    pRespImpl(
        std::make_shared<SPDMResponderImpl>(ioc, conn, trans, pSpdmConfig))
{}

bool SPDMResponder::updateSPDMPool(spdm_transport::TransportEndPoint& endPoint)
{
    return pRespImpl->updateSPDMPool(endPoint);
}

SPDMResponder::~SPDMResponder() noexcept = default;
} // namespace spdm_app_lib