using System.Collections;

namespace Upuaut.Core.Buffers;

/// <summary>
/// A high-performance, bounded, thread-safe ring buffer for streaming diagnostic items.
/// </summary>
public class RingBuffer<T> : IEnumerable<T>
{
    private readonly T[] _buffer;
    private readonly object _lock = new();
    private int _head;
    private int _tail;
    private int _count;

    public int Capacity { get; }
    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _count;
            }
        }
    }

    public RingBuffer(int capacity)
    {
        if (capacity <= 0)
            throw new ArgumentOutOfRangeException(nameof(capacity), "Capacity must be positive.");

        Capacity = capacity;
        _buffer = new T[capacity];
    }

    public void Add(T item)
    {
        lock (_lock)
        {
            _buffer[_tail] = item;
            _tail = (_tail + 1) % Capacity;

            if (_count < Capacity)
            {
                _count++;
            }
            else
            {
                _head = (_head + 1) % Capacity;
            }
        }
    }

    public IReadOnlyList<T> ToSnapshot()
    {
        lock (_lock)
        {
            var result = new List<T>(_count);
            for (int i = 0; i < _count; i++)
            {
                result.Add(_buffer[(_head + i) % Capacity]);
            }
            return result;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _head = 0;
            _tail = 0;
            _count = 0;
            Array.Clear(_buffer, 0, _buffer.Length);
        }
    }

    public IEnumerator<T> GetEnumerator()
    {
        return ToSnapshot().GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}
