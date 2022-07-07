
#pragma once
#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
using namespace sdbusplus;
namespace spdmtransport
{
/**
 * @brief Defind callback function prototype
 *
 * @param ptransEP Pointer to transportEndPoint object.
 * @param data Pointer to a buffer.
 */

using AddRemoreDeviceCallback = std::function<int(void* ptransEP)>;
using MsgReceiveCallback =
    std::function<void(void* ptransEP, const std::vector<uint8_t>& data)>;

/**
 * @brief SPDM Transport type, could be extended.
 *
 */
enum class TransportIdentifier : uint8_t
{
    mctpOverSmBus = 0x01,
    pmtWatcher = 0x02, /*Intel specific transport*/
    SDSi = 0x03        // SDSi
};

/**
 * @brief Endpoint information, could be extended.
 *
 */
typedef struct
{
    TransportIdentifier transType; /*interface type.*/
    uint8_t devIdentifer;
} transportEndPoint;

/**
 * @brief SPDM transport layer class.
 *
 **/

class spdmTransport
{
  public:
    virtual ~spdmTransport() = default;

    /* APIs for requester and responder */
    /**
     * @brief Initial function of transport instance
     *
     * @param  io                boost io_service object.
     * @param  conn              shared_ptr to already existing boost
     *asio::connection.
     * @param  addCB             The callback function for new endpoint
     *detected.
     * @param  delCB             The callback function for EndPoint removed.
     * @param  msgRcvCB          The callback function for messages received(for
     *responder used).
     * @return 0: success, other: failed.
     **/
    virtual int initTransport(
        std::shared_ptr<boost::asio::io_service> io,
        std::shared_ptr<sdbusplus::asio::connection> conn,
        AddRemoreDeviceCallback addCB, AddRemoreDeviceCallback delCB,
        MsgReceiveCallback msgRcvCB =
            nullptr) = 0; // override this function in implementation
                          /**
                           * @brief Get the interface type of transport layer
                           * @return TransportIdentifier
                           *
                           **/
    virtual TransportIdentifier getTransType(void) = 0;

    /****************************************************
        APIs to responder and interface that implementation should override
    these pure virtual functions
    ******************************************************/
    /**
     * @brief The async send data function for responder
     *  nonblocking function to send message to remote endpoint.
     *
     * @param  ptransEP          pointer to destination endpoint.
     * @param  requestSize       The size of data to be sent.
     * @param  request           The buffer pointer of data.
     * @param  timeout           The timeout time.
     * @return 0: success, other: failed.
     *
     **/
    virtual int asyncSendData(transportEndPoint* ptransEP, uint32_t requestSize,
                              const void* request, uint64_t timeout) = 0;

    /****************************************************
        APIs for requester
    ******************************************************/
    /**
     * @brief The sync send and receive data function for requester
     *  blocking function to send SPDM payload and get response data.
     *
     * @param  ptransEP          pointer to destination endpoint.
     * @param  requestSize       The size of data to be sent.
     * @param  request           The buffer pointer of data.
     * @param  timeout           The timeout time.
     * @param  rspRcvCB          The resRcvCB to be called when response data
     *received.
     * @return 0: success, other: failed.
     *
     **/
    virtual int syncSendRecvData(transportEndPoint* ptransEP,
                                 uint32_t requestSize, const void* request,
                                 uint64_t timeout,
                                 MsgReceiveCallback rspRcvCB) = 0;
};

} // namespace spdmtransport