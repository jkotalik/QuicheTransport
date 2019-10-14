using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Transport.Quiche
{
    internal unsafe static class NativeMethods
    {
        internal const string _dllName = "quiche.dll";

        internal const uint QuicheProtocolVersion = 0xff000017;
        internal const int QuicheMaxConnIdLen = 20;
        internal const int QuicheMinClientInitialLen = 1200;

        internal enum QuicheError
        {
            // There is no more work to do.
            QUICHE_ERR_DONE = -1,

            // The provided buffer is too short.
            QUICHE_ERR_BUFFER_TOO_SHORT = -2,

            // The provided packet cannot be parsed because its version is unknown.
            QUICHE_ERR_UNKNOWN_VERSION = -3,

            // The provided packet cannot be parsed because it contains an invalid
            // frame.
            QUICHE_ERR_INVALID_FRAME = -4,

            // The provided packet cannot be parsed.
            QUICHE_ERR_INVALID_PACKET = -5,

            // The operation cannot be completed because the connection is in an
            // invalid state.
            QUICHE_ERR_INVALID_STATE = -6,

            // The operation cannot be completed because the stream is in an
            // invalid state.
            QUICHE_ERR_INVALID_STREAM_STATE = -7,

            // The peer's transport params cannot be parsed.
            QUICHE_ERR_INVALID_TRANSPORT_PARAM = -8,

            // A cryptographic operation failed.
            QUICHE_ERR_CRYPTO_FAIL = -9,

            // The TLS handshake failed.
            QUICHE_ERR_TLS_FAIL = -10,

            // The peer violated the local flow control limits.
            QUICHE_ERR_FLOW_CONTROL = -11,

            // The peer violated the local stream limits.
            QUICHE_ERR_STREAM_LIMIT = -12,

            // The received data exceeds the stream's final size.
            QUICHE_ERR_FINAL_SIZE = -13,
        }

        [DllImport(_dllName)]
        private static extern IntPtr quiche_version();

        public static string QuicheVersion()
        {
            var version = quiche_version();
            return Marshal.PtrToStringAuto(version);
        }

        public delegate void LoggingCallback([MarshalAs(UnmanagedType.LPStr)]string line, IntPtr argp);

        [DllImport(_dllName)]
        // (void (*cb)(const char *line, void *argp), void* argp
        private static extern int quiche_enable_debug_logging(LoggingCallback cb, IntPtr argp);

        public static int QuicheEnableDebugLogging(LoggingCallback cb, IntPtr argp)
        {
            return quiche_enable_debug_logging(cb, argp);
        }
        // typedef struct Config quiche_config;

        [DllImport(_dllName)]
        private static extern IntPtr quiche_config_new(uint version);

        public static IntPtr QuicheConfigNew()
        {
            return quiche_config_new(QuicheProtocolVersion);
        }

        [DllImport(_dllName)]
        private static extern int quiche_config_load_cert_chain_from_pem_file(IntPtr config, [MarshalAs(UnmanagedType.LPStr)] string path);

        public static int QuicheConfigLoadCertChainFromPemFile(IntPtr config, string path)
        {
            return quiche_config_load_cert_chain_from_pem_file(config, path);
        }

        [DllImport(_dllName)]
        // Configures the given private key.
        private static extern int quiche_config_load_priv_key_from_pem_file(IntPtr config, [MarshalAs(UnmanagedType.LPStr)] string path);

        public static int QuicheConfigLoadPrivKeyFromPemFile(IntPtr config, string path)
        {
            return quiche_config_load_priv_key_from_pem_file(config, path);
        }

        [DllImport(_dllName)]
        // Configures whether to verify the peer's certificate.
        private static extern void quiche_config_verify_peer(IntPtr config, bool v);

        public static void QuicheConfigVerifyPeer(IntPtr config, bool v)
        {
            quiche_config_verify_peer(config, v);
        }

        [DllImport(_dllName)]
        // Configures whether to send GREASE.
        private static extern void quiche_config_grease(IntPtr config, bool v);
        public static void QuicheConfigGrease(IntPtr config, bool v)
        {
            quiche_config_grease(config, v);
        }

        [DllImport(_dllName)]
        // Enables logging of secrets.
        private static extern void quiche_config_log_keys(IntPtr config);
        public static void QuicheConfigLogKeys(IntPtr config)
        {
            quiche_config_log_keys(config);
        }

        [DllImport(_dllName)]
        // Configures the list of supported application protocols.
        private static extern int quiche_config_set_application_protos(IntPtr config,
                                         byte* protos,
                                         uint protos_len);
        public static int QuicheConfigSetApplicationProtos(IntPtr config, byte[] protos)
        {
            fixed(byte* protoPtr = protos)
            {
                return quiche_config_set_application_protos(config, protoPtr, (uint)protos.Length);
            }
        }

        [DllImport(_dllName)]
        // Sets the `idle_timeout` transport parameter.
        private static extern void quiche_config_set_idle_timeout(IntPtr config, ulong v);

        public static void QuicheConfigSetIdleTimeout(IntPtr config, ulong v)
        {
            quiche_config_set_idle_timeout(config, v);
        }

        [DllImport(_dllName)]
        // Sets the `max_packet_size` transport parameter.
        private static extern void quiche_config_set_max_packet_size(IntPtr config, ulong v);
        public static void QuicheConfigSetMaxPacketSize(IntPtr config, ulong v)
        {
            quiche_config_set_max_packet_size(config, v);
        }

        [DllImport(_dllName)]
        // Sets the `initial_max_data` transport parameter.
        private static extern void quiche_config_set_initial_max_data(IntPtr config, ulong v);
        public static void QuicheConfigSetInitialMaxData(IntPtr config, ulong v)
        {
            quiche_config_set_initial_max_data(config, v);
        }

        [DllImport(_dllName)]
        // Sets the `initial_max_stream_data_bidi_local` transport parameter.
        private static extern void quiche_config_set_initial_max_stream_data_bidi_local(IntPtr config, ulong v);
        public static void QuicheConfigSetInitialMaxStreamDataBidiLocal(IntPtr config, ulong v)
        {
            quiche_config_set_initial_max_stream_data_bidi_local(config, v);
        }

        [DllImport(_dllName)]
        // Sets the `initial_max_stream_data_bidi_remote` transport parameter.
        private static extern void quiche_config_set_initial_max_stream_data_bidi_remote(IntPtr config, ulong v);
        public static void QuicheConfigSetInitialMaxStreamDataBidiRemote(IntPtr config, ulong v)
        {
            quiche_config_set_initial_max_stream_data_bidi_remote(config, v);
        }

        [DllImport(_dllName)]
        // Sets the `initial_max_stream_data_uni` transport parameter.
        private static extern void quiche_config_set_initial_max_stream_data_uni(IntPtr config, ulong v);
        public static void QuicheConfigSetInitialMaxStreamDataUni(IntPtr config, ulong v)
        {
            quiche_config_set_initial_max_stream_data_uni(config, v);
        }

        [DllImport(_dllName)]
        // Sets the `initial_max_streams_bidi` transport parameter.
        private static extern void quiche_config_set_initial_max_streams_bidi(IntPtr config, ulong v);
        public static void QuicheConfigSetInitialMaxStreamsBidi(IntPtr config, ulong v)
        {
            quiche_config_set_initial_max_streams_bidi(config, v);
        }

        [DllImport(_dllName)]
        // Sets the `initial_max_streams_uni` transport parameter.
        private static extern void quiche_config_set_initial_max_streams_uni(IntPtr config, ulong v);
        public static void QuicheConfigSetInitialMaxStreamsUni(IntPtr config, ulong v)
        {
            quiche_config_set_initial_max_streams_uni(config, v);
        }

        [DllImport(_dllName)]
        // Sets the `ack_delay_exponent` transport parameter.
        private static extern void quiche_config_set_ack_delay_exponent(IntPtr config, ulong v);
        public static void QuicheConfigSetAckDelayExponent(IntPtr config, ulong v)
        {
            quiche_config_set_ack_delay_exponent(config, v);
        }

        [DllImport(_dllName)]
        // Sets the `max_ack_delay` transport parameter.
        private static extern void quiche_config_set_max_ack_delay(IntPtr config, ulong v);
        public static void QuicheConfigSetMaxAckDelay(IntPtr config, ulong v)
        {
            quiche_config_set_max_ack_delay(config, v);
        }

        [DllImport(_dllName)]
        // Sets the `disable_active_migration` transport parameter.
        private static extern void quiche_config_set_disable_active_migration(IntPtr config, bool v);
        public static void QuicheConfigSetDisableActiveMigration(IntPtr config, bool v)
        {
            quiche_config_set_disable_active_migration(config, v);
        }

        [DllImport(_dllName)]
        // Frees the config object.
        private static extern void quiche_config_free(IntPtr config);
        public static void QuicheConfigFree(IntPtr config)
        {
            quiche_config_free(config);
        }

        [DllImport(_dllName)]
        // Extracts version, type, source / destination connection ID and address
        // verification token from the packet in |buf|.
        private static extern int quiche_header_info(byte* buf, uint buf_len, uint dcil,
                               out uint version, out byte type,
                               byte[] scid, out uint scid_len,
                               byte[] dcid, out uint dcid_len,
                               byte[] token, out uint token_len);

        public static int QuicheHeaderInfo(byte[] buf, uint length, uint dcil, out uint version, out byte type, byte[] scid, out uint scid_len, byte[] dcid, out uint dcid_len, byte[] token, out uint token_len)
        {
            fixed (byte* buffer = buf)
            {
                return quiche_header_info(buffer, length, dcil, out version, out type, scid, out scid_len, dcid, out dcid_len, token, out token_len);
            }
        }


        // A QUIC connection.
        //typedef struct Connection quiche_conn;

        [DllImport(_dllName)]
        // Creates a new server-side connection.
        private static extern IntPtr quiche_accept(byte* scid, uint scid_len,
                                   byte* odcid, uint odcid_len,
                                   IntPtr config);

        [DllImport(_dllName)]
        // Creates a new client-side connection.
        private static extern IntPtr quiche_connect(char* server_name, byte* scid,
                                    uint scid_len, IntPtr config);

        [DllImport(_dllName)]
        // Writes a version negotiation packet.
        private static extern uint quiche_negotiate_version(byte* scid, uint scid_len,
                                  byte* dcid, uint dcid_len,
                                 byte* outBytes, uint out_len);

        [DllImport(_dllName)]
        // Writes a retry packet.
        private static extern uint quiche_retry(byte* scid, uint scid_len,
                      byte* dcid, uint dcid_len,
                      byte* new_scid, uint new_scid_len,
                      byte* token, uint token_len,
                     byte* outBytes, uint out_len);

        [DllImport(_dllName)]
        private static extern IntPtr quiche_conn_new_with_tls(byte* scid, uint scid_len,
                                       byte* odcid, uint odcid_len,
                                      IntPtr config, void* ssl,
                                      bool is_server);

        [DllImport(_dllName)]
        // Processes QUIC packets received from the peer.
        private static extern uint quiche_conn_recv(IntPtr conn, byte* buf, uint buf_len);

        [DllImport(_dllName)]
        // Writes a single QUIC packet to be sent to the peer.
        private static extern uint quiche_conn_send(IntPtr conn, byte* outBytes, uint out_len);

        // Buffer holding data at a specific offset.
        //typedef struct RangeBuf quiche_rangebuf;

        [DllImport(_dllName)]
        // Reads contiguous data from a stream.
        private static extern uint quiche_conn_stream_recv(IntPtr conn, ulong stream_id,
                                byte* outBytes, uint buf_len, bool* fin);

        [DllImport(_dllName)]
        // Writes data to a stream.
        private static extern uint quiche_conn_stream_send(IntPtr conn, ulong stream_id,
                                 byte* buf, uint buf_len, bool fin);

        enum quiche_shutdown
        {
            QUICHE_SHUTDOWN_READ = 0,
            QUICHE_SHUTDOWN_WRITE = 1,
        };

        // Shuts down reading or writing from/to the specified stream.
        [DllImport(_dllName)]
        private static extern int quiche_conn_stream_shutdown(IntPtr conn, ulong stream_id,
                                quiche_shutdown direction, ulong err);

        [DllImport(_dllName)]
        private static extern uint quiche_conn_stream_capacity(IntPtr conn, ulong stream_id);

        // Returns true if all the data has been read from the specified stream.
        [DllImport(_dllName)]
        private static extern bool quiche_conn_stream_finished(IntPtr conn, ulong stream_id);

        //typedef struct StreamIter quiche_stream_iter;

        // Returns an iterator over streams that have outstanding data to read.
        [DllImport(_dllName)]
        private static extern IntPtr quiche_conn_readable(IntPtr conn);

        // Returns an iterator over streams that can be written to.
        [DllImport(_dllName)]
        private static extern IntPtr quiche_conn_writable(IntPtr conn);

        // Returns the amount of time until the next timeout event, in nanoseconds.
        [DllImport(_dllName)]
        private static extern ulong quiche_conn_timeout_as_nanos(IntPtr conn);

        // Returns the amount of time until the next timeout event, in milliseconds.
        [DllImport(_dllName)]
        private static extern ulong quiche_conn_timeout_as_millis(IntPtr conn);

        // Processes a timeout event.
        [DllImport(_dllName)]
        private static extern void quiche_conn_on_timeout(IntPtr conn);

        // Closes the connection with the given error and reason.
        [DllImport(_dllName)]
        private static extern int quiche_conn_close(IntPtr conn, bool app, ulong err,
                       byte* reason, uint reason_len);

        // Returns the negotiated ALPN protocol.
        [DllImport(_dllName)]
        private static extern void quiche_conn_application_proto(IntPtr conn, byte** outBytes,
                                   uint* out_len);

        // Returns true if the connection handshake is complete.
        [DllImport(_dllName)]
        private static extern bool quiche_conn_is_established(IntPtr conn);

        // Returns true if the connection is closed.
        [DllImport(_dllName)]
        private static extern bool quiche_conn_is_closed(IntPtr conn);

        // Fetches the next stream from the given iterator. Returns false if there are
        // no more elements in the iterator.
        [DllImport(_dllName)]
        private static extern bool quiche_stream_iter_next(IntPtr iter, ulong* stream_id);

        // Frees the given stream iterator object.
        [DllImport(_dllName)]
        private static extern void quiche_stream_iter_free(IntPtr iter);

        [StructLayout(LayoutKind.Sequential)]
        internal struct quiche_stats
        {
            // The number of QUIC packets received on this connection.
            uint recv;

            // The number of QUIC packets sent on this connection.
            uint sent;

            // The number of QUIC packets that were lost.
            uint lost;

            // The estimated round-trip time of the connection (in nanoseconds).
            ulong rtt;

            // The size in bytes of the connection's congestion window.
            uint cwnd;
        }

        // Collects and returns statistics about the connection.
        [DllImport(_dllName)]
        private static extern void quiche_conn_stats(IntPtr conn, quiche_stats* outStats);

        // Frees the connection object.
        [DllImport(_dllName)]
        private static extern void quiche_conn_free(IntPtr conn);

    }
}
