using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using Newtonsoft.Json;
using StackExchange.Redis;

namespace database.Redis
{
    public class RedisHub
    {
        private readonly string _connectionString;
        private Lazy<ConnectionMultiplexer> _lazyConnection;

        private readonly IConfiguration _configuration;
        public RedisHub(IConfiguration configuration)
        {
            _configuration = configuration;
            _connectionString = _configuration["RedisConnectionString"] ?? "";
            _lazyConnection ??= CreateConnection();
        }

        public string Host => _connectionString.Split(",")[0].Split(":")[0];
        public string Port => _connectionString.Split(",")[0].Split(":")[1];

        public ConnectionMultiplexer Connection
        {
            get
            {
                _lazyConnection ??= CreateConnection();
                return _lazyConnection.Value;
            }
        }
        private Lazy<ConnectionMultiplexer> CreateConnection()
        {
            return new Lazy<ConnectionMultiplexer>(() =>
            {
                string cacheConnection = _connectionString;
                return ConnectionMultiplexer.Connect(cacheConnection);
            });
        }
        private long _lastReconnectTicks = DateTimeOffset.MinValue.UtcTicks;
        private DateTimeOffset _firstErrorTime = DateTimeOffset.MinValue;
        private DateTimeOffset _previousErrorTime = DateTimeOffset.MinValue;

        private readonly object _reconnectLock = new object();

        // In general, let StackExchange.Redis handle most reconnects,
        // so limit the frequency of how often ForceReconnect() will
        // actually reconnect.
        private TimeSpan ReconnectMinFrequency => TimeSpan.FromSeconds(60);

        // If errors continue for longer than the below threshold, then the
        // multiplexer seems to not be reconnecting, so ForceReconnect() will
        // re-create the multiplexer.
        private TimeSpan ReconnectErrorThreshold => TimeSpan.FromSeconds(30);

        private int RetryMaxAttempts => 5;

        private void CloseConnection()
        {
            if (_lazyConnection == null)
                return;

            try
            {
                _lazyConnection.Value.Close();
            }
            catch (Exception)
            {
                // Example error condition: if accessing oldConnection.Value causes a connection attempt and that fails.
            }
        }

        /// <summary>
        /// Force a new ConnectionMultiplexer to be created.
        /// NOTES:
        ///     1. Users of the ConnectionMultiplexer MUST handle ObjectDisposedExceptions, which can now happen as a result of calling ForceReconnect().
        ///     2. Don't call ForceReconnect for Timeouts, just for RedisConnectionExceptions or SocketExceptions.
        ///     3. Call this method every time you see a connection exception. The code will:
        ///         a. wait to reconnect for at least the "ReconnectErrorThreshold" time of repeated errors before actually reconnecting
        ///         b. not reconnect more frequently than configured in "ReconnectMinFrequency"
        /// </summary>
        public void ForceReconnect()
        {
            DateTimeOffset utcNow = DateTimeOffset.UtcNow;
            long previousTicks = Interlocked.Read(ref _lastReconnectTicks);
            DateTimeOffset previousReconnectTime = new DateTimeOffset(previousTicks, TimeSpan.Zero);
            TimeSpan elapsedSinceLastReconnect = utcNow - previousReconnectTime;

            // If multiple threads call ForceReconnect at the same time, we only want to honor one of them.
            if (elapsedSinceLastReconnect < ReconnectMinFrequency)
                return;

            lock (_reconnectLock)
            {
                utcNow = DateTimeOffset.UtcNow;
                elapsedSinceLastReconnect = utcNow - previousReconnectTime;

                if (_firstErrorTime == DateTimeOffset.MinValue)
                {
                    // We haven't seen an error since last reconnect, so set initial values.
                    _firstErrorTime = utcNow;
                    _previousErrorTime = utcNow;
                    return;
                }

                if (elapsedSinceLastReconnect < ReconnectMinFrequency)
                    return; // Some other thread made it through the check and the lock, so nothing to do.

                TimeSpan elapsedSinceFirstError = utcNow - _firstErrorTime;
                TimeSpan elapsedSinceMostRecentError = utcNow - _previousErrorTime;

                bool shouldReconnect =
                    elapsedSinceFirstError >= ReconnectErrorThreshold // Make sure we gave the multiplexer enough time to reconnect on its own if it could.
                    && elapsedSinceMostRecentError <= ReconnectErrorThreshold; // Make sure we aren't working on stale data (e.g. if there was a gap in errors, don't reconnect yet).

                // Update the previousErrorTime timestamp to be now (e.g. this reconnect request).
                _previousErrorTime = utcNow;

                if (!shouldReconnect)
                    return;

                _firstErrorTime = DateTimeOffset.MinValue;
                _previousErrorTime = DateTimeOffset.MinValue;

                CloseConnection();
                _lazyConnection = CreateConnection();
                Interlocked.Exchange(ref _lastReconnectTicks, utcNow.UtcTicks);
            }
        }

        // In real applications, consider using a framework such as
        // Polly to make it easier to customize the retry approach.
        private T BasicRetry<T>(Func<T> func)
        {
            int reconnectRetry = 0;
            int disposedRetry = 0;

            while (true)
            {
                try
                {
                    return func();
                }
                catch (Exception ex) when (ex is RedisConnectionException || ex is SocketException)
                {
                    reconnectRetry++;
                    if (reconnectRetry > RetryMaxAttempts)
                        throw;
                    ForceReconnect();
                }
                catch (ObjectDisposedException)
                {
                    disposedRetry++;
                    if (disposedRetry > RetryMaxAttempts)
                        throw;
                }
            }
        }
        public string GetConnectionString() => _connectionString;
        public IDatabase GetDatabase() => BasicRetry(() => _lazyConnection.Value.GetDatabase());
        public System.Net.EndPoint[] GetEndPoints() => BasicRetry(() => _lazyConnection.Value.GetEndPoints());
        public IServer GetServer(string host, int port) => BasicRetry(() => _lazyConnection.Value.GetServer(host, port));
        public string Get(string key) => BasicRetry(() => GetDatabase().StringGet(key));
        public T GetObject<T>(string key) => BasicRetry(() => JsonConvert.DeserializeObject<T>(Get(key)));
        public List<string> GetKeys(string pattern) => BasicRetry(() => GetServer(Host, 6379).Keys(pattern: pattern).Select(p => (string)p).ToList());
        public bool Set(string key, string value) => BasicRetry(() => GetDatabase().StringSet(key, value));
        public bool SetObject(string key, object value) => BasicRetry(() => Set(key, JsonConvert.SerializeObject(value)));
        public bool Delete(string key) => BasicRetry(() => GetDatabase().KeyDelete(key));
        public bool Exist(string key) => BasicRetry(() => GetDatabase().KeyExists(key));
        public RedisValue[] GetList(string key) => BasicRetry(() => GetDatabase().ListRange(key, 0, -1));
    }
}