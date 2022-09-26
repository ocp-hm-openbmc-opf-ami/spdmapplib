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
 * limitation
 */

#include "spdmapplib.hpp"

#include <phosphor-logging/log.hpp>

#include <iostream>
#include <map>

using configurationField =
    std::variant<bool, uint64_t, std::string, std::vector<std::string>>;
using ConfigurationMap = std::unordered_map<std::string, configurationField>;

static const std::string spdmTypeName =
    "xyz.openbmc_project.Configuration.SPDMConfiguration";

/**
 * @brief convert string to integer
 *
 * @param table : source table
 * @param name: string to convert
 * @param value (output): result
 */
static bool getValueFromName(const std::map<std::string, uint32_t>& table,
                             std::string name, uint32_t& value)
{
    auto item = table.find(name);

    if (item == table.end())
    {
        return false;
    }
    // actions when found
    value = item->second;
    return true;
}

/**
 * @brief get configuration map from entity manager
 *
 * @param conn shared_ptr to already existing boost asio::connection
 * object. Usable if invoker is sdbus aware and uses asio::connection for
 * some other purposes.
 * @param configurationPath : path
 */
static ConfigurationMap
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
    ConfigurationMap map;
    reply.read(map);

    return map;
}

/**
 * @brief get field from ConfigurationMap
 *
 * @param map : map of configuration
 * @param fieldName : string of field
 * @param value (output) : result
 */

template <typename T>
static bool getField(const ConfigurationMap& map, const std::string& fieldName,
                     T& value)
{
    auto it = map.find(fieldName);
    if (it == map.end())
    {
        return false;
    }
    const T* ptrValue = std::get_if<T>(&it->second);
    if (ptrValue != nullptr)
    {
        value = *ptrValue;
        return true;
    }
    else
    {
        return false;
    }
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
    phosphor::logging::log<phosphor::logging::level::ERR>(
        ("getSPDMConfigurationPaths Get config path of  " + spdmConfig)
            .c_str());
    try
    {
        auto methodCall = conn->new_method_call(
            "xyz.openbmc_project.ObjectMapper",
            "/xyz/openbmc_project/object_mapper",
            "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");

        methodCall.append("/xyz/openbmc_project/inventory/system/board", 2,
                          std::array<std::string, 1>({spdmTypeName}));

        auto reply = conn->call(methodCall);
        reply.read(paths);
    }
    catch (const std::exception& exceptionIn)
    {
        std::string exceptionStr = exceptionIn.what();
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("getSPDMConfigurationPaths Exception: " + exceptionStr).c_str());
        return configPath;
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("getSPDMConfigurationPaths Checking config path of " + spdmConfig)
            .c_str());

    if (paths.size() > 0)
    {
        for (std::string& cfgPath : paths)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("getSPDMConfigurationPaths Checking : " + cfgPath).c_str());
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
template <typename T>
bool getSPDMConfigData(T& spdmConfig, std::vector<std::string>& spdmUserConfig,
                       const std::map<std::string, uint32_t> spdmConfigVerifier)
{
    T spdmConfigData;
    for (std::string& entry : spdmUserConfig)
    {
        spdmConfigData = 0;

        if (!getValueFromName(spdmConfigVerifier, entry, spdmConfigData))
        {
            spdmUserConfig.clear();
            return false;
        }
        spdmConfig = spdmConfig | spdmConfigData;
    }
    spdmUserConfig.clear();
    return true;
}
/**
 * @brief get configuration from entitymanager
 *
 * @param conn: shared_ptr to already existing boost asio::connection
 * object. Usable if invoker is sdbus aware and uses asio::connection for
 * some other purposes.
 * @param configurationName : string of configuration
 * @return SPDM configuration
 */

spdm_app_lib::SPDMConfiguration getConfigurationFromEntityManager(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    const std::string& configurationName)
{
    uint64_t slotCount = 0;
    std::string spdmStrConfig{};
    std::vector<std::string> spdmUserConfig{};
    spdm_app_lib::SPDMConfiguration spdmConfig{};
    const std::string objectPath =
        getSPDMConfigurationPaths(conn, configurationName);

    ConfigurationMap map{};
    if (objectPath.empty())
    {
        return spdmConfig;
    }
    try
    {
        map = getConfigurationMap(conn, objectPath);
    }
    catch (const std::exception& exceptionIn)
    {
        return spdmConfig;
    }

    if (getField(map, "CertPath", spdmStrConfig))
    {
        spdmConfig.certPath = std::move(spdmStrConfig);
    }
    else
    {
        spdmConfig.certPath = "/usr/share/spdmd/sample_keys";
    }

    if (!getField(map, "Version", spdmStrConfig))
    {
        return spdmConfig;
    }
    if (!getValueFromName(spdm_app_lib::getSPDMConfigMap(
                              spdm_app_lib::SPDMConfigIdentifier::version),
                          spdmStrConfig, spdmConfig.version))
    {
        return spdmConfig;
    }

    if (!getField(map, "Capability", spdmUserConfig))
    {
        return spdmConfig;
    }
    if (!getSPDMConfigData(
            spdmConfig.capability, spdmUserConfig,
            spdm_app_lib::getSPDMConfigMap(
                spdm_app_lib::SPDMConfigIdentifier::requesterCaps)))
    {
        return spdmConfig;
    }

    if (!getField(map, "Hash", spdmUserConfig))
    {
        return spdmConfig;
    }
    if (!getSPDMConfigData(spdmConfig.hash, spdmUserConfig,
                           spdm_app_lib::getSPDMConfigMap(
                               spdm_app_lib::SPDMConfigIdentifier::baseHash)))
    {
        return spdmConfig;
    }

    if (!getField(map, "MeasHash", spdmUserConfig))
    {
        return spdmConfig;
    }
    if (!getSPDMConfigData(spdmConfig.measHash, spdmUserConfig,
                           spdm_app_lib::getSPDMConfigMap(
                               spdm_app_lib::SPDMConfigIdentifier::measHash)))
    {
        return spdmConfig;
    }

    if (!getField(map, "Asym", spdmUserConfig))
    {
        return spdmConfig;
    }
    if (!getSPDMConfigData(spdmConfig.asym, spdmUserConfig,
                           spdm_app_lib::getSPDMConfigMap(
                               spdm_app_lib::SPDMConfigIdentifier::asymHash)))
    {
        return spdmConfig;
    }

    if (!getField(map, "ReqAsym", spdmUserConfig))
    {
        return spdmConfig;
    }
    if (!getSPDMConfigData(spdmConfig.reqasym, spdmUserConfig,
                           spdm_app_lib::getSPDMConfigMap(
                               spdm_app_lib::SPDMConfigIdentifier::asymHash)))
    {
        return spdmConfig;
    }

    if (!getField(map, "Dhe", spdmUserConfig))
    {
        return spdmConfig;
    }
    if (!getSPDMConfigData(spdmConfig.dhe, spdmUserConfig,
                           spdm_app_lib::getSPDMConfigMap(
                               spdm_app_lib::SPDMConfigIdentifier::dheValue)))
    {
        return spdmConfig;
    }

    if (!getField(map, "Aead", spdmUserConfig))
    {
        return spdmConfig;
    }
    if (!getSPDMConfigData(spdmConfig.aead, spdmUserConfig,
                           spdm_app_lib::getSPDMConfigMap(
                               spdm_app_lib::SPDMConfigIdentifier::aeadValue)))
    {
        return spdmConfig;
    }

    if (!getField(map, "SlotCount", slotCount))
    {
        return spdmConfig;
    }
    spdmConfig.slotcount = static_cast<uint32_t>(slotCount);

    return spdmConfig;
}
