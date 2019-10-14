// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Transport.Quiche
{
    internal class QuicheTransportFactory : IConnectionListenerFactory
    {
        private QuicheTransportContext _transportContext;

        public QuicheTransportFactory(IHostApplicationLifetime applicationLifetime, ILoggerFactory loggerFactory, IOptions<QuicheTransportOptions> options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (loggerFactory == null)
            {
                throw new ArgumentNullException(nameof(loggerFactory));
            }

            var logger = loggerFactory.CreateLogger("Transport.Quiche");
            var trace = new QuicheTrace(logger);
            InitializeQuiche();

            _transportContext = new QuicheTransportContext(applicationLifetime, trace, options.Value);
        }

        private void DebugLog(string line, IntPtr argp)
        {
            // TODO argp may need to be used here. 
            _transportContext.Log.LogDebug(line);
        }

        private void InitializeQuiche(CancellationToken cancellationToken = default)
        {
            NativeMethods.QuicheEnableDebugLogging(DebugLog, IntPtr.Zero);
            var config = NativeMethods.QuicheConfigNew();

            // Config stuff
            // TODO figure out how paths work here :)
            var val = NativeMethods.QuicheConfigLoadCertChainFromPemFile(config, "cert.crt");
            val = NativeMethods.QuicheConfigLoadPrivKeyFromPemFile(config, "cert.key");
            val = NativeMethods.QuicheConfigSetApplicationProtos(config, Encoding.ASCII.GetBytes("\x05h3-23\x08http/0.9"));

            NativeMethods.QuicheConfigSetIdleTimeout(config, 500000000);
            NativeMethods.QuicheConfigSetMaxPacketSize(config, 1350);
            NativeMethods.QuicheConfigSetInitialMaxData(config, 10000000);
            NativeMethods.QuicheConfigSetInitialMaxStreamDataBidiLocal(config, 1000000);
            NativeMethods.QuicheConfigSetInitialMaxStreamDataBidiRemote(config, 1000000);
            NativeMethods.QuicheConfigSetInitialMaxStreamsBidi(config, 100);
        }

        public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
        {
            var transport = new QuicheConnectionListener(_transportContext, endpoint);
            transport.Bind();
            return new ValueTask<IConnectionListener>(transport);
        }
    }
}