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

#include "spdmapplib_requester_impl.hpp"
#include "spdmapplib_responder_impl.hpp"
#include "spdmtransport.hpp"

namespace spdm_app_lib
{
std::map<std::string, uint32_t> versionValueStringTable = {
    {"1.0", SPDM_MESSAGE_VERSION_10},
    {"1.1", SPDM_MESSAGE_VERSION_11},
    {"1.2", SPDM_MESSAGE_VERSION_12},
};

std::map<std::string, uint32_t> securedMessageVersionValueStringTable = {
    {"0", 0},
    {"1.0", SPDM_MESSAGE_VERSION_10},
    {"1.1", SPDM_MESSAGE_VERSION_11},
};

std::map<std::string, uint32_t> spdmRequesterCapabilitiesStringTable = {
    {"CERT", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP},
    {"CHAL", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP},
    {"ENCRYPT", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP},
    {"MAC", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP},
    {"MUT_AUTH", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP},
    {"KEY_EX", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP},
    {"PSK", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER},
    {"ENCAP", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP},
    {"HBEAT", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP},
    {"KEY_UPD", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP},
    {"HANDSHAKE_IN_CLEAR",
     SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP},
    {"PUB_KEY_ID", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP},
    {"CHUNK", SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP},
};

std::map<std::string, uint32_t> spdmResponderCapabilitiesStringTable = {
    {"CACHE", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP},
    {"CERT", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP},
    {"CHAL", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP},
    {"MEAS_NO_SIG", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG},
    {"MEAS_SIG", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG},
    {"MEAS_FRESH", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP},
    {"ENCRYPT", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP},
    {"MAC", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP},
    {"MUT_AUTH", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP},
    {"KEY_EX", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP},
    {"PSK", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER},
    {"PSK_WITH_CONTEXT",
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT},
    {"ENCAP", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP},
    {"HBEAT", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP},
    {"KEY_UPD", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP},
    {"HANDSHAKE_IN_CLEAR",
     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP},
    {"PUB_KEY_ID", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP},
    {"CHUNK", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP},
    {"ALIAS_CERT", SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP},
};

std::map<std::string, uint32_t> hashValueStringTable{
    {"SHA_256", SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256},
    {"SHA_384", SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384},
    {"SHA_512", SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512},
    {"SHA3_256", SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256},
    {"SHA3_384", SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384},
    {"SHA3_512", SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512},
    {"SM3_256", SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256},
};

std::map<std::string, uint32_t> measurementHashValueStringTable = {
    {"RAW_BIT", SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY},
    {"SHA_256", SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256},
    {"SHA_384", SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384},
    {"SHA_512", SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512},
    {"SHA3_256", SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256},
    {"SHA3_384", SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384},
    {"SHA3_512", SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512},
    {"SM3_256", SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256},
};

std::map<std::string, uint32_t> asymValueStringTable = {
    {"RSASSA_2048", SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048},
    {"RSASSA_3072", SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072},
    {"RSASSA_4096", SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096},
    {"RSAPSS_2048", SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048},
    {"RSAPSS_3072", SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072},
    {"RSAPSS_4096", SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096},
    {"ECDSA_P256", SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256},
    {"ECDSA_P384", SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384},
    {"ECDSA_P521", SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521},
    {"SM2_P256", SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256},
    {"EDDSA_25519", SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519},
    {"EDDSA_448", SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448},
};

std::map<std::string, uint32_t> dheValueStringTable = {
    {"FFDHE_2048", SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048},
    {"FFDHE_3072", SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072},
    {"FFDHE_4096", SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096},
    {"SECP_256_R1", SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1},
    {"SECP_384_R1", SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1},
    {"SECP_521_R1", SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1},
    {"SM2_P256", SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256},
};

std::map<std::string, uint32_t> aeadValueStringTable = {
    {"AES_128_GCM", SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM},
    {"AES_256_GCM", SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM},
    {"CHACHA20_POLY1305", SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305},
    {"SM4_128_GCM", SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM},
};

std::map<std::string, uint32_t> basicMutAuthPolicyStringTable = {
    {"NO", 0},
    {"BASIC", 1},
};

std::map<std::string, uint32_t> mutAuthPolicyStringTable = {
    {"NO", 0},
    {"WO_ENCAP", SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED},
    {"W_ENCAP",
     SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST},
    {"DIGESTS", SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS},
};

std::map<SPDMConfigIdentifier, std::map<std::string, uint32_t>>
    spdmConfigValues{
        {SPDMConfigIdentifier::version, versionValueStringTable},
        {SPDMConfigIdentifier::secureVersion,
         securedMessageVersionValueStringTable},
        {SPDMConfigIdentifier::requesterCaps,
         spdmRequesterCapabilitiesStringTable},
        {SPDMConfigIdentifier::responderCaps,
         spdmResponderCapabilitiesStringTable},
        {SPDMConfigIdentifier::baseHash, hashValueStringTable},
        {SPDMConfigIdentifier::measHash, measurementHashValueStringTable},
        {SPDMConfigIdentifier::asymHash, asymValueStringTable},
        {SPDMConfigIdentifier::dheValue, dheValueStringTable},
        {SPDMConfigIdentifier::aeadValue, aeadValueStringTable},
        {SPDMConfigIdentifier::basicMutualSupport,
         basicMutAuthPolicyStringTable},
        {SPDMConfigIdentifier::mutualAuthValue, mutAuthPolicyStringTable}};

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

std::map<std::string, uint32_t>
    getSPDMConfigMap(SPDMConfigIdentifier configIdentifier)
{
    std::map<std::string, uint32_t> spdmConfigMap{};
    for (auto const& spdmConfigMapIter : spdmConfigValues)
    {
        if (spdmConfigMapIter.first == configIdentifier)
        {
            spdmConfigMap = spdmConfigMapIter.second;
            break;
        }
    }
    return spdmConfigMap;
}
} // namespace spdm_app_lib