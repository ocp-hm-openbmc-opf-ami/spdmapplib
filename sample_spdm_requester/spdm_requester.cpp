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

#include "spdmapplib.hpp"
#include "spdmtransport_mctp.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/object_server.hpp>

#include <iostream>
#include <unordered_set>
#include <iomanip>
#include <sstream>

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

static void printBinary(uint32_t value)
{
    for (int i = 31; i >= 0; i--)
    {
        std::cout << ((value >> i) & 1);
    }
}

static void printCurrentConfiguration()
{
    std::cout << "Version: ";
    printBinary(spdmRequesterCfg.version);
    std::cout << std::endl;

    std::cout << "Capability: ";
    printBinary(spdmRequesterCfg.capability);
    std::cout << std::endl;

    std::cout << "ASYM Algorithm: ";
    printBinary(spdmRequesterCfg.asym);
    std::cout << std::endl;

    std::cout << "Hash Algorithm: ";
    printBinary(spdmRequesterCfg.hash);
    std::cout << std::endl;

    std::cout << "Certificate: " << spdmRequesterCfg.certPath << std::endl;

    std::cout << "DHE Algorithm: ";
    printBinary(spdmRequesterCfg.dhe);
    std::cout << std::endl;

    std::cout << "AEAD Algorithm: ";
    printBinary(spdmRequesterCfg.aead);
    std::cout << std::endl;

    std::cout << "reqasym Algorithm: ";
    printBinary(spdmRequesterCfg.reqasym);
    std::cout << std::endl;

    std::cout << "measHash Algorithm: ";
    printBinary(spdmRequesterCfg.measHash);
    std::cout << std::endl;
}

/**
 * @brief Main function of SPDM requester unit test.
 *
 */
static void startSPDMRequester()
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Staring SPDM requester!!");

    printCurrentConfiguration();

    trans->initDiscovery([&](spdm_transport::TransportEndPoint eidPoint,
                             spdm_transport::Event event) {
        if (event == spdm_transport::Event::added)
        {
            std::cerr << "Added eid: " << std::to_string(eidPoint.devIdentifier)
                      << "\n";
            auto spdmRequester = std::make_shared<spdm_app_lib::SPDMRequester>(
                ioc, conn, trans, eidPoint, spdmRequesterCfg);
            std::vector<uint8_t> data = {};
            constexpr uint8_t slot0 = 0;
            constexpr uint8_t slot1 = 1;

            /** Test case 1 get certificate from slot 0 */
            if (spdmRequester->getCertificate(data, slot0))
            {
                std::cout << "Dump certificate raw data from slot 0."
                          << std::endl;
                dumpVector(data);
            }
            else
            {
                std::cerr << "Failed to get certificate from slot 0 for EID: "
                          << std::to_string(eidPoint.devIdentifier)
                          << std::endl;
                return;
            }
            data.clear();

            /** Test case 2 get certificate from slot 1 */
            if (spdmRequester->getCertificate(data, slot1))
            {
                std::cout << "Dump certificate raw data from slot 1."
                          << std::endl;
                dumpVector(data);
            }
            else
            {
                std::cerr << "Failed to get certificate from slot 1 for EID: "
                          << std::to_string(eidPoint.devIdentifier)
                          << std::endl;
                return;
            }
            data.clear();

            /** Test case 3 get measurement with certificate in slot 0 */
            if (spdmRequester->getMeasurements(data, slot0))
            {
                std::cout
                    << "Dump measurement raw data with certificate in slot 0."
                    << std::endl;
                dumpVector(data);
            }
            else
            {
                std::cerr
                    << "Failed to get measurement raw data with certificate in slot 0 for EID: "
                    << std::to_string(eidPoint.devIdentifier) << std::endl;
                return;
            }
            data.clear();

            /** Test case 4 get measurement with certificate in slot 1 */
            if (spdmRequester->getMeasurements(data, slot1))
            {
                std::cout
                    << "Dump measurement raw data with certificate in slot 1."
                    << std::endl;
                dumpVector(data);
            }
            else
            {
                std::cerr
                    << "Failed to get measurement raw data with certificate in slot 1 for EID: "
                    << std::to_string(eidPoint.devIdentifier) << std::endl;
                return;
            }
            data.clear();

            /** Test case 5 start secure session by using certificate in slot 0
             * and no pre-shared key */
            uint32_t sessionId = 0;
            uint8_t heartbeatPeriod = 0;
            constexpr bool notUsePsk = false;
            if (spdmRequester->startSecureSession(notUsePsk, sessionId,
                                                  heartbeatPeriod, slot0))
            {
                std::cout
                    << "Started secure session with slot-0 certificate successfully."
                    << std::endl
                    << "Session ID: " << sessionId << std::endl
                    << "Heartbeat period: " << static_cast<int>(heartbeatPeriod)
                    << " seconds." << std::endl;
            }
            else
            {
                std::cerr
                    << "Failed to start secure session with slot-0 certificate."
                    << std::endl;
                return;
            }

            /** Test case 6 send heartbeat */
            if (spdmRequester->sendHeartbeat(sessionId))
            {
                std::cout << "Heartbeat sent successfully." << std::endl;
            }
            else
            {
                std::cerr << "Failed to send heartbeat" << std::endl
                          << "Session ID: " << sessionId << std::endl;
                return;
            }

            /** Test case 7 update key in single direction */
            if (spdmRequester->updateKey(sessionId, false))
            {
                std::cout << "Update key in single direction successfully."
                          << std::endl;
            }
            else
            {
                std::cerr << "Failed to update key in single direction"
                          << std::endl
                          << "Session ID: " << sessionId << std::endl;
                return;
            }

            /** Test case 8 update key */
            if (spdmRequester->updateKey(sessionId, true))
            {
                std::cout << "Update key successfully." << std::endl;
            }
            else
            {
                std::cerr << "Failed to update key" << std::endl
                          << "Session ID: " << sessionId << std::endl;
                return;
            }

            /** Test case 9 send application message over secure channel */
            constexpr uint8_t mctpMessageTypePldm = 0x01;
            constexpr uint8_t instanceId = 0;
            constexpr uint8_t pldmHeaderRequestMask = 0x80;
            constexpr uint8_t pldmMessageTypeControlDiscovery = 0x00;
            constexpr uint8_t pldmControlDiscoveryCommandGetTid = 0x02;
            std::vector<uint8_t> request = {
                mctpMessageTypePldm, instanceId | pldmHeaderRequestMask,
                pldmMessageTypeControlDiscovery,
                pldmControlDiscoveryCommandGetTid};
            std::vector<uint8_t> response;
            /**
             * The sample uses PLDM content as plain data which is encapsulated
             * with MCTP and encypted within secured channel. If you want to
             * send MCTP application message. Please ensure
             *  1. Pass true as isAppMessage argument into sendSecuredMessage
             * method.
             *  2. Ensure SPDM responder side recognized this special format and
             * then sent back something.
             *  Note: SPDM or secured-message payload which starts with
             * 0x05 or 0x06 cannot be considered as an APP message. Pass false
             * as isAppMessage argument instead.
             */
            constexpr bool isAppMessage = true;
            if (spdmRequester->sendSecuredMessage(sessionId, request, response,
                                                  isAppMessage))
            {
                std::cout << "Secured application message sent successfully."
                          << std::endl;
                std::ostringstream oss;
                oss << "Request: ";
                for (const auto& byte : request)
                {
                    oss << "0x" << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<int>(byte) << ' ';
                }
                oss << std::endl;
                oss << "Response: ";
                for (const auto& byte : response)
                {
                    oss << "0x" << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<int>(byte) << ' ';
                }
                oss << std::endl;
                std::cout << oss.str() << std::endl;
            }
            else
            {
                std::cerr << "Failed to send secured messages." << std::endl
                          << "Session ID: " << sessionId << std::endl;
                return;
            }

            /** Test case 10 terminate the secure session */
            if (spdmRequester->endSecureSession(sessionId))
            {
                std::cout << "Terminate the secure session successfully."
                          << std::endl;
            }
            else
            {
                std::cerr << "Failed to terminate the secure session."
                          << std::endl
                          << "Session ID: " << sessionId << std::endl;
                return;
            }

            /** Test case 11 start secure session by using certificate in slot 1
             * and pre-shared key */
            constexpr bool usePsk = true;
            sessionId = 0;
            if (spdmRequester->startSecureSession(usePsk, sessionId,
                                                  heartbeatPeriod, slot1))
            {
                std::cout
                    << "Started secure session with pre-shared key successfully."
                    << std::endl
                    << "Session ID: " << sessionId << std::endl
                    << "Heartbeat period: " << static_cast<int>(heartbeatPeriod)
                    << " seconds." << std::endl;
            }
            else
            {
                std::cerr
                    << "Failed to start secure session with pre-shared key."
                    << std::endl;
                return;
            }

            /** Test case 12 terminate the secure session */
            if (spdmRequester->endSecureSession(sessionId))
            {
                std::cout << "Terminate the secure session successfully."
                          << std::endl;
            }
            else
            {
                std::cerr << "Failed to terminate the secure session."
                          << std::endl
                          << "Session ID: " << sessionId << std::endl;
                return;
            }
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
