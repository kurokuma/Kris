namespace MRTW.Core;

/// <summary>
/// Thread-safe, first-in bounded capture storage.  Items received after the
/// limit are counted but never retained, so a noisy target cannot exhaust the
/// case process before it can finish monitoring and write collection quality.
/// </summary>
public sealed class BoundedCaptureBuffer<T>
{
    private readonly object _sync = new();
    private readonly List<T> _items = [];
    private long _received;
    private long _dropped;

    public BoundedCaptureBuffer(int capacity)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        Capacity = capacity;
    }

    public int Capacity { get; }
    public long Received => Interlocked.Read(ref _received);
    public long Dropped => Interlocked.Read(ref _dropped);
    public int Count { get { lock (_sync) return _items.Count; } }

    public bool TryAdd(T item)
    {
        Interlocked.Increment(ref _received);
        lock (_sync)
        {
            if (_items.Count >= Capacity)
            {
                Interlocked.Increment(ref _dropped);
                return false;
            }

            _items.Add(item);
            return true;
        }
    }

    public T[] ToArray()
    {
        lock (_sync) return _items.ToArray();
    }
}
