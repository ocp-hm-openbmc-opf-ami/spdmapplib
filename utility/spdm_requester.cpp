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
#include "spdmtransport_mctp.hpp"

#include <CLI/CLI.hpp>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>

#include <iostream>
/**
 * @brief Function to display Unit test menu.
 *
 */

void displayMenu(void)
{
    std::cerr << "1: do_authentication()" << std::endl;
    std::cerr << "2: do_measurement()" << std::endl;
    std::cerr << "3: get_certificate()" << std::endl;
    std::cerr << "4: get_measurements()" << std::endl;
    std::cerr << "0: Quit" << std::endl;
}

/**
 * @brief Function to dump values of input vector.
 *
 * @param vec : The vector to be dumped
 */
void dumpVector(std::vector<unsigned char> vec)
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
int main(int argc, char* argv[])
{
    auto pspdmRequester = spdmapplib::createRequester();
    spdmtransport::transportEndPoint responderCfg = {
        spdmtransport::TransportIdentifier::mctpOverSmBus, 0};
    auto ioc = std::make_shared<boost::asio::io_context>();
    auto conn = std::make_shared<sdbusplus::asio::connection>(*ioc);
    auto trans = std::make_shared<spdmtransport::spdmTransportMCTP>(
        spdmtransport::TransportIdentifier::mctpOverSmBus);
    boost::asio::steady_timer timer(*ioc);
    uint8_t eid;
    CLI::App app("SPDM requester verify tool");
    app.add_option("--eid", eid, "Responder MCTP EID    : uint8_t")->required();
    CLI11_PARSE(app, argc, argv);

    std::cerr << "Assigned responder EID: " << static_cast<uint16_t>(eid)
              << std::endl;
    responderCfg.devIdentifer = eid;

    if (pspdmRequester->initRequester(
            ioc, conn, trans,
            static_cast<spdmtransport::transportEndPoint*>(&responderCfg)) == 0)
    {
        std::cerr << "spdm_requester started." << std::endl;
        boost::asio::spawn(*(ioc), [&](boost::asio::yield_context yield) {
            UNUSED(yield);
            int selTest = 0;
            timer.expires_after(std::chrono::seconds(1));
            timer.async_wait([&](boost::system::error_code ec) {
                if (ec == boost::asio::error::operation_aborted)
                {
                    return;
                }
                else if (ec)
                {
                    std::cerr << "Timer error " << ec.message() << std::endl;
                    return;
                }
                bool testRun = true;
                while (testRun)
                {
                    displayMenu();
                    std::cerr << "Enter test selection Number: ";
                    std::cin >> selTest;
                    std::cerr << "\nThe selection is " << selTest << std::endl;
                    switch (selTest)
                    {
                        case 1:
                            std::cerr << "Execute do_authentication()."
                                      << std::endl;
                            pspdmRequester->do_authentication();
                            break;
                        case 2:
                            std::cerr << "Execute do_measurement()."
                                      << std::endl;
                            pspdmRequester->do_measurement(NULL);
                            break;
                        case 3:
                            std::cerr << "Execute get_certificate()."
                                      << std::endl;
                            dumpVector(
                                pspdmRequester->get_certificate().value());
                            break;
                        case 4:
                            std::cerr << "Execute get_measurements()."
                                      << std::endl;
                            dumpVector(
                                pspdmRequester->get_measurements().value());
                            break;
                        default:
                            testRun = false;
                            std::cerr << "Quit!" << std::endl;
                    }
                }
                ioc->stop();
            });
        });

        ioc->run();
    }
    else
    {
        std::cerr << "spdm_requester init failed." << std::endl;
    }
    return 0;
}
