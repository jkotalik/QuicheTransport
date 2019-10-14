// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Transport.Quiche
{
    internal class QuicheConnectionListener : IConnectionListener
    {
        private Socket _listenSocket;
        private readonly MemoryPool<byte> _memoryPool;

        private static readonly int MinAllocBufferSize = SlabMemoryPool.BlockSize / 2;
        private static readonly bool IsWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        private static readonly bool IsMacOS = RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

        private readonly IQuicheTrace _trace;
        private SocketReceiver _receiver;
        private SocketSender _sender;
        private Task _processingTask;

        private IAsyncEnumerator<QuicheStream> _acceptEnumerator;
        private bool _socketDisposed;
        private volatile Exception _shutdownReason;
        private readonly CancellationTokenSource _connectionClosedTokenSource = new CancellationTokenSource();
        private readonly TaskCompletionSource<object> _waitForConnectionClosedTcs = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly object _shutdownLock = new object();


        private readonly Channel<QuicheStream> _acceptQueue = Channel.CreateUnbounded<QuicheStream>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true
        });

        public QuicheConnectionListener(QuicheTransportContext transportContext, EndPoint endpoint)
        {
            TransportContext = transportContext;
            EndPoint = endpoint;
            _memoryPool = transportContext.MemoryPoolFactory();

            var inputOptions = new PipeOptions(MemoryPool, PipeScheduler.ThreadPool, PipeScheduler.ThreadPool, 4096, 4096 / 2, useSynchronizationContext: false);
            var outputOptions = new PipeOptions(MemoryPool, PipeScheduler.ThreadPool, PipeScheduler.ThreadPool, 4096, 4096 / 2, useSynchronizationContext: false);

            var pair = DuplexPipe.CreateConnectionPair(inputOptions, outputOptions);
            Input = pair.Application.Output;
            Output = pair.Application.Input;

            TransportInput = pair.Transport.Input;
            TransportOutput = pair.Transport.Output;
        }

        public PipeWriter Input { get; }
        public PipeReader TransportInput { get; }

        public PipeReader Output { get; }
        public PipeWriter TransportOutput { get; }

        public MemoryPool<byte> MemoryPool { get; }

        public QuicheTransportContext TransportContext { get; }
        public EndPoint EndPoint { get; set; }
        public IHostApplicationLifetime AppLifetime => TransportContext.AppLifetime;
        public ILogger Log => TransportContext.Log;

        public async ValueTask<ConnectionContext> AcceptAsync(CancellationToken cancellationToken = default)
        {

            if (await _acceptEnumerator.MoveNextAsync())
            {
                return _acceptEnumerator.Current;
            }

            return null;

            //while (true)
            //{
            //    try
            //    {
            //        // start the connection, wait for a stream to occur.
            //        // Iasyncenumerable for streams here.
            //    }
            //    catch (ObjectDisposedException)
            //    {
            //        // A call was made to UnbindAsync/DisposeAsync just return null which signals we're done
            //        return null;
            //    }
            //    catch (SocketException e) when (e.SocketErrorCode == SocketError.OperationAborted)
            //    {
            //        // A call was made to UnbindAsync/DisposeAsync just return null which signals we're done
            //        return null;
            //    }
            //    catch (SocketException)
            //    {
            //        // The connection got reset while it was in the backlog, so we try again.
            //        TransportContext.Log.ConnectionReset("TODO connections aren't here": "(null)");
            //    }
            //}
        }

        internal void Bind()
        {
            var listenSocket = new Socket(EndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

            if (EndPoint is IPEndPoint ip && ip.Address == IPAddress.IPv6Any)
            {
                listenSocket.DualMode = true;
            }

            try
            {
                listenSocket.Bind(EndPoint);
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                throw new AddressInUseException(e.Message, e);
            }

            EndPoint = listenSocket.LocalEndPoint;

            _listenSocket = listenSocket;

            var awaiterScheduler = IsWindows ? PipeScheduler.ThreadPool : PipeScheduler.Inline;

            _receiver = new SocketReceiver(_listenSocket, awaiterScheduler);
            _sender = new SocketSender(_listenSocket, awaiterScheduler);

            _processingTask = StartAsync();
            _acceptEnumerator = AcceptStreamsAsync();
        }

        private async IAsyncEnumerator<QuicheStream> AcceptStreamsAsync()
        {
            while (true)
            {
                while (await _acceptQueue.Reader.WaitToReadAsync())
                {
                    while (_acceptQueue.Reader.TryRead(out var stream))
                    {
                        yield return stream;
                    }
                }

                yield return null;
            }
        }

        private async Task StartAsync()
        {
            try
            {
                // Spawn send and receive logic
                var receiveTask = DoReceive();
                var sendTask = DoSend();

                // Now wait for both to complete
                await receiveTask;
                await sendTask;

                _receiver.Dispose();
                _sender.Dispose();
            }
            catch (Exception ex)
            {
                _trace.LogError(0, ex, $"Unexpected exception in {nameof(QuicheConnectionListener)}.{nameof(StartAsync)}.");
            }
        }

        private async Task DoReceive()
        {
            Exception error = null;

            try
            {
                await ProcessReceives();
            }
            catch (SocketException ex) when (IsConnectionResetError(ex.SocketErrorCode))
            {
                // This could be ignored if _shutdownReason is already set.
                error = new ConnectionResetException(ex.Message, ex);

                // There's still a small chance that both DoReceive() and DoSend() can log the same connection reset.
                // Both logs will have the same "TODO connections aren't here". I don't think it's worthwhile to lock just to avoid this.
                if (!_socketDisposed)
                {
                    _trace.ConnectionReset("TODO connections aren't here");
                }
            }
            catch (Exception ex)
                when ((ex is SocketException socketEx && IsConnectionAbortError(socketEx.SocketErrorCode)) ||
                       ex is ObjectDisposedException)
            {
                // This exception should always be ignored because _shutdownReason should be set.
                error = ex;

                if (!_socketDisposed)
                {
                    // This is unexpected if the socket hasn't been disposed yet.
                    _trace.ConnectionError("TODO connections aren't here", error);
                }
            }
            catch (Exception ex)
            {
                // This is unexpected.
                error = ex;
                _trace.ConnectionError("TODO connections aren't here", error);
            }
            finally
            {
                // If Shutdown() has already bee called, assume that was the reason ProcessReceives() exited.
                Input.Complete(_shutdownReason ?? error);

                //FireConnectionClosed();

                await _waitForConnectionClosedTcs.Task;
            }
        }

        private async Task ProcessReceives()
        {
            // Resolve `input` PipeWriter via the IDuplexPipe interface prior to loop start for performance.
            var input = Input;
            while (true)
            {
                // Wait for data before allocating a buffer.
                await _receiver.WaitForDataAsync();

                // Ensure we have some reasonable amount of buffer space
                var buffer = input.GetMemory(MinAllocBufferSize);

                var bytesReceived = await _receiver.ReceiveAsync(buffer);

                if (bytesReceived == 0)
                {
                    // FIN
                    _trace.ConnectionReadFin("TODO connections aren't here");
                    break;
                }

                input.Advance(bytesReceived);

                var flushTask = input.FlushAsync();

                var paused = !flushTask.IsCompleted;

                if (paused)
                {
                    _trace.ConnectionPause("TODO connections aren't here");
                }

                var result = await flushTask;

                if (paused)
                {
                    _trace.ConnectionResume("TODO connections aren't here");
                }

                if (result.IsCompleted || result.IsCanceled)
                {
                    // Pipe consumer is shut down, do we stop writing
                    break;
                }
            }
        }

        private async Task DoSend()
        {
            Exception shutdownReason = null;
            Exception unexpectedError = null;

            try
            {
                await ProcessSends();
            }
            catch (SocketException ex) when (IsConnectionResetError(ex.SocketErrorCode))
            {
                shutdownReason = new ConnectionResetException(ex.Message, ex);
                _trace.ConnectionReset("TODO connections aren't here");
            }
            catch (Exception ex)
                when ((ex is SocketException socketEx && IsConnectionAbortError(socketEx.SocketErrorCode)) ||
                       ex is ObjectDisposedException)
            {
                // This should always be ignored since Shutdown() must have already been called by Abort().
                shutdownReason = ex;
            }
            catch (Exception ex)
            {
                shutdownReason = ex;
                unexpectedError = ex;
                _trace.ConnectionError("TODO connections aren't here", unexpectedError);
            }
            finally
            {
                Shutdown(shutdownReason);

                // Complete the output after disposing the socket
                Output.Complete(unexpectedError);

                // Cancel any pending flushes so that the input loop is un-paused
                Input.CancelPendingFlush();
            }
        }

        private async Task ProcessSends()
        {
            // Resolve `output` PipeReader via the IDuplexPipe interface prior to loop start for performance.
            var output = Output;
            while (true)
            {
                var result = await output.ReadAsync();

                if (result.IsCanceled)
                {
                    break;
                }

                var buffer = result.Buffer;

                var end = buffer.End;
                var isCompleted = result.IsCompleted;
                if (!buffer.IsEmpty)
                {
                    await _sender.SendAsync(buffer);
                }

                output.AdvanceTo(end);

                if (isCompleted)
                {
                    break;
                }
            }
        }


        //private void FireConnectionClosed()
        //{
        //    // Guard against scheduling this multiple times
        //    if (_connectionClosed)
        //    {
        //        return;
        //    }
        //    // TODO this kind of needs to be translated?

        //    _connectionClosed = true;

        //    ThreadPool.UnsafeQueueUserWorkItem(state =>
        //    {
        //        state.CancelConnectionClosedToken();

        //        state._waitForConnectionClosedTcs.TrySetResult(null);
        //    },
        //    this,
        //    preferLocal: false);
        //}

        private void Shutdown(Exception shutdownReason)
        {
            lock (_shutdownLock)
            {
                if (_socketDisposed)
                {
                    return;
                }

                // Make sure to close the connection only after the _aborted flag is set.
                // Without this, the RequestsCanBeAbortedMidRead test will sometimes fail when
                // a BadHttpRequestException is thrown instead of a TaskCanceledException.
                _socketDisposed = true;

                // shutdownReason should only be null if the output was completed gracefully, so no one should ever
                // ever observe the nondescript ConnectionAbortedException except for connection middleware attempting
                // to half close the connection which is currently unsupported.
                _shutdownReason = shutdownReason ?? new ConnectionAbortedException("The Socket transport's send loop completed gracefully.");

                _trace.ConnectionWriteFin("TODO connections aren't here", _shutdownReason.Message);

                try
                {
                    // Try to gracefully close the socket even for aborts to match libuv behavior.
                    _listenSocket.Shutdown(SocketShutdown.Both);
                }
                catch
                {
                    // Ignore any errors from Socket.Shutdown() since we're tearing down the connection anyway.
                }

                _listenSocket.Dispose();
            }
        }

        private void CancelConnectionClosedToken()
        {
            try
            {
                _connectionClosedTokenSource.Cancel();
            }
            catch (Exception ex)
            {
                _trace.LogError(0, ex, $"Unexpected exception in {nameof(QuicheConnectionListener)}.{nameof(CancelConnectionClosedToken)}.");
            }
        }

        private static bool IsConnectionResetError(SocketError errorCode)
        {
            // A connection reset can be reported as SocketError.ConnectionAborted on Windows.
            // ProtocolType can be removed once https://github.com/dotnet/corefx/issues/31927 is fixed.
            return errorCode == SocketError.ConnectionReset ||
                   errorCode == SocketError.Shutdown ||
                   (errorCode == SocketError.ConnectionAborted && IsWindows) ||
                   (errorCode == SocketError.ProtocolType && IsMacOS);
        }

        private static bool IsConnectionAbortError(SocketError errorCode)
        {
            // Calling Dispose after ReceiveAsync can cause an "InvalidArgument" error on *nix.
            return errorCode == SocketError.OperationAborted ||
                   errorCode == SocketError.Interrupted ||
                   (errorCode == SocketError.InvalidArgument && !IsWindows);
        }

        public ValueTask UnbindAsync(CancellationToken cancellationToken = default)
        {
            _listenSocket?.Dispose();
            return default;
        }

        public async ValueTask DisposeAsync()
        {
            _listenSocket?.Dispose();
            // Dispose the memory pool
            _memoryPool.Dispose();

            Input.Complete();
            Output.Complete();

            if (_processingTask != null)
            {
                await _processingTask;
            }

            //_connectionClosedTokenSource.Dispose();
        }


        public async Task DoTransportReceive()
        {
            while (true)
            {
                var memory = await TransportInput.ReadAsync();

                var scid = new byte[100];
                var dcid = new byte[100];
                var token = new byte[1000];

                // TODO perf here.
                var arr = memory.Buffer.ToArray();
                var rc = NativeMethods.QuicheHeaderInfo(arr, (uint)memory.Buffer.Length, dcil: 16, out uint version, out byte type, scid, out uint scid_len, dcid, out uint dcid_len, token, out uint token_len);
            }
        }
    }
}