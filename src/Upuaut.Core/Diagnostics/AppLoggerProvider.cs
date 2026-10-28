using Microsoft.Extensions.Logging;

namespace Upuaut.Core.Diagnostics;

public class AppLoggerProvider : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName)
    {
        return new AppLoggerAdapter(categoryName);
    }

    public void Dispose()
    {
    }

    private sealed class AppLoggerAdapter : ILogger
    {
        private readonly string _category;

        public AppLoggerAdapter(string category)
        {
            _category = category;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            switch (logLevel)
            {
                case Microsoft.Extensions.Logging.LogLevel.Trace:
                case Microsoft.Extensions.Logging.LogLevel.Debug:
                    AppLogger.Debug(_category, message);
                    break;
                case Microsoft.Extensions.Logging.LogLevel.Information:
                    AppLogger.Info(_category, message);
                    break;
                case Microsoft.Extensions.Logging.LogLevel.Warning:
                    AppLogger.Warning(_category, message, exception);
                    break;
                case Microsoft.Extensions.Logging.LogLevel.Error:
                    AppLogger.Error(_category, message, exception);
                    break;
                case Microsoft.Extensions.Logging.LogLevel.Critical:
                    AppLogger.Fatal(_category, message, exception);
                    break;
            }
        }
    }
}
