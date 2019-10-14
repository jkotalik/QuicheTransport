// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Buffers;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Transport.Quiche
{
    internal class QuicheTransportContext
    {
        public QuicheTransportContext(IHostApplicationLifetime appLifetime, IQuicheTrace log, QuicheTransportOptions options)
        {
            AppLifetime = appLifetime;
            Log = log;
            Options = options;
        }

        public IHostApplicationLifetime AppLifetime { get; }
        public IQuicheTrace Log { get; }
        public QuicheTransportOptions Options { get; }
        internal Func<MemoryPool<byte>> MemoryPoolFactory { get; set; } = System.Buffers.SlabMemoryPoolFactory.Create;
    }
}