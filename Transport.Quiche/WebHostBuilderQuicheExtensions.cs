// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.DependencyInjection;
using Transport.Quiche;

namespace Microsoft.AspNetCore.Hosting
{
    public static class WebHostBuilderMsQuicExtensions
    {
        public static IWebHostBuilder UseQuiche(this IWebHostBuilder hostBuilder)
        {
            return hostBuilder.ConfigureServices(services =>
            {
                services.AddSingleton<IConnectionListenerFactory, QuicheTransportFactory>();
            });
        }

        public static IWebHostBuilder UseQuiche(this IWebHostBuilder hostBuilder, Action<QuicheTransportOptions> configureOptions)
        {
            return hostBuilder.UseQuiche().ConfigureServices(services =>
            {
                services.Configure(configureOptions);
            });
        }
    }
}
