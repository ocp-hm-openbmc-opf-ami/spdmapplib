
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
    errGetCFG = 1, // SPDM configuration not found in EntityManager.
};

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
                      std::shared_ptr<spdmtransport::spdmTransport> trans) = 0;
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
                      spdmtransport::transportEndPoint* ptransResponder) = 0;
    /**
     * @brief The authentication function
     *
     * @return 0: success, other: failed.
     **/
    virtual int do_authentication(void) = 0;
    /**
     * @brief The measurement function
     *
     * @param  sessionid          The session id pointer(reserved for futher
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
