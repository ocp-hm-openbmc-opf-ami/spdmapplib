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
#include "spdmtransport_mctp.hpp"

#include <CLI/CLI.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <iostream>
#include <unordered_set>
#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

extern spdm_app_lib::SPDMConfiguration getConfigurationFromEntityManager(
    std::shared_ptr<sdbusplus::asio::connection> conn,
    const std::string& configurationName);

static std::shared_ptr<boost::asio::io_context> ioc =
    std::make_shared<boost::asio::io_context>();
static std::shared_ptr<sdbusplus::asio::connection> conn =
    std::make_shared<sdbusplus::asio::connection>(*ioc);
static auto trans = std::make_shared<spdm_transport::SPDMTransportMCTP>(
    ioc, conn, mctpw::BindingType::mctpOverSmBus);

static spdm_app_lib::SPDMConfiguration spdmRequesterCfg{};

using ConfigurationField =
    std::variant<bool, uint64_t, std::string, std::vector<uint64_t>>;

using ConfigurationMap = std::unordered_map<std::string, ConfigurationField>;

static const std::string spdmTypeName =
    "xyz.openbmc_project.Configuration.SPDMConfiguration";

static std::unordered_set<std::string> startedUnits;

/**
 * @brief Function to get SPDM configuration path in EntityManager.
 *
 */
static std::vector<std::string> getConfigurationPaths()
{
    auto method_call = conn->new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");

    method_call.append("/xyz/openbmc_project/inventory/system/board", 2,
                       std::array<std::string, 1>({spdmTypeName}));

    auto reply = conn->call(method_call);
    std::vector<std::string> paths;
    reply.read(paths);
    return paths;
}

/**
 * @brief Function to dump values of input vector.
 *
 * @param vec : The vector to be dumped
 */
static void dumpVector(std::vector<unsigned char> vec)
{
    std::cerr << __func__ << " size: " << vec.size() << std::hex << std::endl;
    for (unsigned int i = 0; i < vec.size(); ++i)
    {
        std::cerr << std::setw(3) << static_cast<uint16_t>(vec[i]);
        if (((i + 1) % 32) == 0)
        {
            std::cerr << std::endl;
        }
    }
    std::cerr << std::dec << std::endl;
}

/**
 * @brief Main function of SPDM requester unit test.
 *
 */
static void startSPDMRequester()
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Staring SPDM requester!!");

    trans->initDiscovery([&](spdm_transport::TransportEndPoint eidPoint,
                             spdm_transport::Event event) {
        if (event == spdm_transport::Event::added)
        {
            std::cerr << "Added eid: " << std::to_string(eidPoint.devIdentifier)
                      << "\n";
            auto spdmRequester = std::make_shared<spdm_app_lib::SPDMRequester>(
                ioc, conn, trans, eidPoint, spdmRequesterCfg);
            std::vector<uint8_t> data = {};
            if (spdmRequester->getCertificate(data))
            {
                dumpVector(data);
            }
            else
            {
                std::cerr << "Failed getting Certificate for EID: "
                          << std::to_string(eidPoint.devIdentifier) << "\n";
            }
            data.clear();
            if (spdmRequester->getMeasurements(data))
            {
                dumpVector(data);
            }
            else
            {
                std::cerr << "Failed getting Measurements for EID: "
                          << std::to_string(eidPoint.devIdentifier) << "\n";
            }
            data.clear();
        }
        else if (event == spdm_transport::Event::removed)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "Remove the device from the inventory");
        }
    });
}

/**
 * @brief Function to start SPDM requester function test.
 *
 * @param spdmConfig : The configuration name to in entitymanager.
 */

static void startExistingConfigurations(std::string& spdmConfig)
{
    std::vector<std::string> configurationPaths;
    try
    {
        configurationPaths = getConfigurationPaths();
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            (std::string("Could not retrieve existing configurations: ") +
             e.what())
                .c_str());
        return;
    }

    for (const auto& objectPath : configurationPaths)
    {
        if (startedUnits.count(objectPath) != 0)
        {
            continue;
        }
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            (std::string("Found config: ") + objectPath).c_str());

        if (objectPath.find(spdmConfig) != objectPath.npos)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("Matched : " + spdmConfig + "! Reading configuration from" +
                 objectPath)
                    .c_str());
            spdmRequesterCfg =
                getConfigurationFromEntityManager(conn, spdmConfig);
            startSPDMRequester();
        }
    }
}

int main()
{
    std::string requesterConfigName{"SPDM_requester"};

    startExistingConfigurations(requesterConfigName);

    if (spdmRequesterCfg.version)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDM requester started.");
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDM requester configuration not found!!");
    }
    std::vector<std::string> units;

    namespace rules = sdbusplus::bus::match::rules;

    auto match = std::make_unique<sdbusplus::bus::match::match>(
        *conn,
        rules::interfacesAdded() + rules::path_namespace("/") +
            rules::sender("xyz.openbmc_project.EntityManager"),
        [&units, &requesterConfigName](sdbusplus::message::message& message) {
            if (message.is_method_error())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Callback method error");
                return;
            }
            sdbusplus::message::object_path unitPath;
            std::unordered_map<std::string, ConfigurationMap> interfacesAdded;
            try
            {
                message.read(unitPath, interfacesAdded);
            }
            catch (const std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Message read error");
                return;
            }

            if (startedUnits.count(unitPath) != 0)
            {
                return;
            }
            for (const auto& interface : interfacesAdded)
            {
                if (interface.first != spdmTypeName)
                {
                    continue;
                }
                std::cerr << "Config found in match rule!" << std::endl;
                if (spdmRequesterCfg.version)
                {
                    std::cerr << "spdm requester had started before."
                              << std::endl;
                }
                else
                {
                    std::cerr << "spdm requester starting..." << std::endl;
                    startExistingConfigurations(requesterConfigName);
                }
            }
        });

    boost::asio::signal_set signals(*ioc, SIGINT, SIGTERM);
    signals.async_wait(
        [](const boost::system::error_code&, const int&) { ioc->stop(); });

    ioc->run();
    return 0;
}
