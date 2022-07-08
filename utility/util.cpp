/**
 * Copyright © 2020 Intel Corporation
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
 * limitation
 */

#include "spdmapplib.hpp"
extern "C"
{
#include "library/spdm_common_lib.h"
}
#include <iostream>

using configurationField =
    std::variant<bool, uint64_t, std::string, std::vector<std::string>>;
using configurationMap = std::unordered_map<std::string, configurationField>;

char* setCertPath = NULL;

typedef struct
{
    uint32_t value;
    char* name;
} valueStringEntry;

valueStringEntry versionValueStringTable[] = {
    {SPDM_MESSAGE_VERSION_10, "1.0"},
    {SPDM_MESSAGE_VERSION_11, "1.1"},
    {SPDM_MESSAGE_VERSION_12, "1.2"},
};

valueStringEntry securedMessageVersionValueStringTable[] = {
    {0, "0"},
    {SPDM_MESSAGE_VERSION_10, "1.0"},
    {SPDM_MESSAGE_VERSION_11, "1.1"},
};

valueStringEntry spdmRequesterCapabilitiesSringTable[] = {
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, "CERT"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP, "CHAL"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP, "ENCRYPT"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP, "MAC"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, "MUT_AUTH"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, "KEY_EX"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER, "PSK"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP, "ENCAP"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP, "HBEAT"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP, "KEY_UPD"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
     "HANDSHAKE_IN_CLEAR"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, "PUB_KEY_ID"},
    {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP, "CHUNK"},
};

valueStringEntry spdmResponderCapabilitiesStringTable[] = {
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP, "CACHE"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP, "CERT"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP, "CHAL"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG, "MEAS_NO_SIG"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG, "MEAS_SIG"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP, "MEAS_FRESH"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP, "ENCRYPT"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP, "MAC"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP, "MUT_AUTH"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP, "KEY_EX"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER, "PSK"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT,
     "PSK_WITH_CONTEXT"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP, "ENCAP"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP, "HBEAT"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP, "KEY_UPD"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
     "HANDSHAKE_IN_CLEAR"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP, "PUB_KEY_ID"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP, "CHUNK"},
    {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP, "ALIAS_CERT"},
};

valueStringEntry hashValueStringTable[] = {
    {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, "SHA_256"},
    {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384, "SHA_384"},
    {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512, "SHA_512"},
    {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256"},
    {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384"},
    {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512"},
    {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256, "SM3_256"},
};

valueStringEntry measurementHashValueStringTable[] = {
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY, "RAW_BIT"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, "SHA_256"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384, "SHA_384"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512, "SHA_512"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256, "SM3_256"},
};

valueStringEntry asymValueStringTable[] = {
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048, "RSASSA_2048"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072, "RSASSA_3072"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096, "RSASSA_4096"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048, "RSAPSS_2048"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072, "RSAPSS_3072"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096, "RSAPSS_4096"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, "ECDSA_P256"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384, "ECDSA_P384"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521, "ECDSA_P521"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256, "SM2_P256"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519, "EDDSA_25519"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448, "EDDSA_448"},
};

valueStringEntry dheValueStringTable[] = {
    {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048, "FFDHE_2048"},
    {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072, "FFDHE_3072"},
    {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096, "FFDHE_4096"},
    {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1, "SECP_256_R1"},
    {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1, "SECP_384_R1"},
    {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1, "SECP_521_R1"},
    {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256, "SM2_P256"},
};

valueStringEntry aeadValueStringTable[] = {
    {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM, "AES_128_GCM"},
    {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM, "AES_256_GCM"},
    {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305, "CHACHA20_POLY1305"},
    {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM, "SM4_128_GCM"},
};

valueStringEntry basicMutAuthPolicyStringTable[] = {
    {0, "NO"},
    {1, "BASIC"},
};

valueStringEntry mutAuthPolicyStringTable[] = {
    {0, "NO"},
    {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED, "WO_ENCAP"},
    {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST,
     "W_ENCAP"},
    {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS, "DIGESTS"},
};

static const std::string spdmTypeName =
    "xyz.openbmc_project.Configuration.SPDMConfiguration";

/**
 * @brief convert string to integer
 *
 * @param table : source table
 * @param entryCount : source table
 * @param name: string to convert
 * @param value (output): result
 */
static bool getValueFromName(const valueStringEntry* table, uint32_t entryCount,
                             std::string name, uint32_t* value)
{
    uint32_t index;

    for (index = 0; index < entryCount; index++)
    {
        if (strcmp(name.c_str(), table[index].name) == 0)
        {
            *value = table[index].value;
            return true;
        }
    }
    return false;
}

/**
 * @brief get configuration map from entity manager
 *
 * @param conn shared_ptr to already existing boost asio::connection
 * object. Usable if invoker is sdbus aware and uses asio::connection for
 * some other purposes.
 * @param configurationPath : path
 */
static configurationMap
    getConfigurationMap(std::shared_ptr<sdbusplus::asio::connection> conn,
                        const std::string& configurationPath)
{

    auto methodCall = conn->new_method_call(
        "xyz.openbmc_project.EntityManager", configurationPath.c_str(),
        "org.freedesktop.DBus.Properties", "GetAll");
    methodCall.append("xyz.openbmc_project.Configuration.SPDMConfiguration");

    // Note: This is a blocking call.
    // However, there is nothing to do until the configuration is retrieved.
    auto reply = conn->call(methodCall);
    configurationMap map;
    reply.read(map);

    return map;
}

/**
 * @brief get field from configurationMap
 *
 * @param map : map of configuration
 * @param fieldName : string of field
 * @param value (output) : result
 */

template <typename T>
static bool getField(const configurationMap& map, const std::string& fieldName,
                     T& value)
{
    auto it = map.find(fieldName);
    if (it != map.end())
    {
        const T* ptrValue = std::get_if<T>(&it->second);
        if (ptrValue != nullptr)
        {
            value = *ptrValue;
            return true;
        }
    }

    return false;
}

/**
 * @brief get SPDM configuration dbus object path of EntityManager.
 *
 * @param conn: shared_ptr to already existing boost asio::connection
 * object. Usable if invoker is sdbus aware and uses asio::connection for
 * some other purposes.
 * @param spdmConfig : string of configuration
 * @return SPDM configuration dbus object path of EntityManager
 */

static std::string
    getSPDMConfigurationPaths(std::shared_ptr<sdbusplus::asio::connection> conn,
                              std::string spdmConfig)
{
    std::string configPath;
    std::vector<std::string> paths;
    std::cerr << "Get config path of " << spdmConfig << std::endl;
    try
    {
        auto method_call = conn->new_method_call(
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");

        method_call.append("/xyz/openbmc_project/inventory/system/board", 2,
                           std::array<std::string, 1>({spdmTypeName}));

        auto reply = conn->call(method_call);
        reply.read(paths);
    }
    catch (const std::exception& e)
    {
        std::cerr << __func__ << ":" << e.what() << std::endl;
        return configPath;
    }

    std::cerr << "Checking config path of " << spdmConfig << std::endl;

    if (paths.size() > 0)
    {
        for (std::string& cfgPath : paths)
        {
            std::cerr << "Checking : " << cfgPath << std::endl;
            if (cfgPath.find(spdmConfig) != cfgPath.npos)
            {
                configPath = cfgPath;
                break;
            }
        }
    }

    return configPath;
}
/*
API to get SPDM configuration from Entity Manager. Called by requester and
responder.
*/

/**
 * @brief get configuration from entitymanager
 *
 * @param conn: shared_ptr to already existing boost asio::connection
 * object. Usable if invoker is sdbus aware and uses asio::connection for
 * some other purposes.
 * @param configurationName : string of configuration
 * @return SPDM configuration
 */

spdmapplib::spdmConfiguration getConfigurationFromEntityManager(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    const std::string& configurationName)
{
    uint32_t i;
    uint32_t u32Data;
    spdmapplib::spdmConfiguration spdmConfig;
    memset(&spdmConfig, 0, sizeof(spdmConfig));
    const std::string objectPath =
        getSPDMConfigurationPaths(conn, configurationName);

    configurationMap map;
    if (objectPath.empty())
    {
        return spdmConfig;
    }
    try
    {
        map = getConfigurationMap(conn, objectPath);
    }
    catch (const std::exception& e)
    {
        return spdmConfig;
    }

    // Get cert file path
    std::string certPath;
    if (!getField(map, "CertPath", certPath))
    {
        setCertPath = (char*)malloc(strlen("/usr/bin") + 1);
        if (setCertPath != NULL)
        {

            strcpy(setCertPath, certPath.c_str());
        }
    }
    else
    {
        setCertPath = (char*)malloc(certPath.size() + 1);
        if (setCertPath != NULL)
        {
            strcpy(setCertPath, certPath.c_str());
        }
    }
    spdmConfig.certPath = setCertPath;

    // get capability
    std::vector<std::string> capability;
    if (!getField(map, "Capability", capability))
    {
        return spdmConfig;
    }

    for (i = 0; i < capability.size(); i++)
    {
        u32Data = 0;

        if (!getValueFromName(spdmResponderCapabilitiesStringTable,
                              sizeof(spdmResponderCapabilitiesStringTable),
                              capability[i], &(u32Data)))
            return spdmConfig;
        spdmConfig.capability = spdmConfig.capability | u32Data;
    }

    // get hash
    std::vector<std::string> hash;
    if (!getField(map, "Hash", hash))
    {
        return spdmConfig;
    }

    for (i = 0; i < hash.size(); i++)
    {
        u32Data = 0;
        if (!getValueFromName(hashValueStringTable,
                              sizeof(hashValueStringTable), hash[i],
                              &(u32Data)))
            return spdmConfig;
        spdmConfig.hash = spdmConfig.hash | u32Data;
    }

    // get meas hash
    std::vector<std::string> measHash;
    if (!getField(map, "MeasHash", measHash))
    {
        return spdmConfig;
    }

    for (i = 0; i < measHash.size(); i++)
    {
        u32Data = 0;
        if (!getValueFromName(measurementHashValueStringTable,
                              sizeof(measurementHashValueStringTable),
                              measHash[i], &(u32Data)))
            return spdmConfig;
        spdmConfig.measHash = spdmConfig.measHash | u32Data;
    }

    // get asym
    std::vector<std::string> asym;
    if (!getField(map, "Asym", asym))
    {
        return spdmConfig;
    }

    for (i = 0; i < asym.size(); i++)
    {
        u32Data = 0;
        if (!getValueFromName(asymValueStringTable,
                              sizeof(asymValueStringTable), asym[i],
                              &(u32Data)))
            return spdmConfig;
        spdmConfig.asym = spdmConfig.asym | u32Data;
    }
    // get reqasym
    std::vector<std::string> reqasym;
    if (!getField(map, "ReqAsym", reqasym))
    {
        return spdmConfig;
    }

    for (i = 0; i < reqasym.size(); i++)
    {
        u32Data = 0;
        if (!getValueFromName(asymValueStringTable,
                              sizeof(asymValueStringTable), reqasym[i],
                              &(u32Data)))
            return spdmConfig;
        spdmConfig.reqasym = spdmConfig.reqasym | u32Data;
    }

    // get dhe
    std::vector<std::string> dhe;
    if (!getField(map, "Dhe", dhe))
    {
        return spdmConfig;
    }

    for (i = 0; i < dhe.size(); i++)
    {
        u32Data = 0;
        if (!getValueFromName(dheValueStringTable, sizeof(dheValueStringTable),
                              dhe[i], &(u32Data)))
            return spdmConfig;
        spdmConfig.dhe = spdmConfig.dhe | u32Data;
    }

    // get aead
    std::vector<std::string> aead;
    if (!getField(map, "Aead", aead))
    {
        return spdmConfig;
    }

    for (i = 0; i < aead.size(); i++)
    {
        u32Data = 0;
        if (!getValueFromName(aeadValueStringTable,
                              sizeof(aeadValueStringTable), aead[i],
                              &(u32Data)))
            return spdmConfig;
        spdmConfig.aead = spdmConfig.aead | u32Data;
    }
    // get SlotCount
    uint64_t slotcount;
    if (!getField(map, "SlotCount", slotcount))
    {
        return spdmConfig;
    }
    spdmConfig.slotcount = (uint32_t)slotcount;
    // Get version
    std::string version;
    if (!getField(map, "Version", version))
    {
        return spdmConfig;
    }
    if (!getValueFromName(versionValueStringTable,
                          sizeof(versionValueStringTable), version,
                          &(spdmConfig.version)))
    {
        return spdmConfig;
    }

#if 0
    // get BasicMutAuth
    std::string basicMutAuth;
    if (!getField(map, "BasicMutAuth", basicMutAuth))
    {
        return spdmConfig;
    }
    if (!getValueFromName(basicMutAuthPolicyStringTable,
                          sizeof(basicMutAuthPolicyStringTable), basicMutAuth,
                          &(spdmConfig.basicMutAuth)))
        return spdmConfig;

    // get MutAuth
    std::string mutAuth;
    if (!getField(map, "MutAuth", mutAuth))
    {
        return spdmConfig;
    }
    if (!getValueFromName(mutAuthPolicyStringTable,
                          sizeof(mutAuthPolicyStringTable), mutAuth,
                          &(spdmConfig.mutAuth)))
        return spdmConfig;
#endif
    return spdmConfig;
}
