namespace MRTW.Core;

/// <summary>UI-thread accumulator that avoids rebuilding immutable case arrays for every incoming event.</summary>
public sealed class LiveBatchAccumulator<T>
{
    private readonly List<T> _items = [];
    public int Count => _items.Count;
    public IReadOnlyList<T> Items => _items;
    public int MaterializationCount { get; private set; }
    public void Clear() { _items.Clear(); MaterializationCount = 0; }
    public void AddRange(IEnumerable<T> values) => _items.AddRange(values);
    public void AddOrderedRange(IEnumerable<T> values, IComparer<T> comparer)
    {
        foreach (var value in values)
        {
            int index = _items.BinarySearch(value, comparer);
            if (index < 0) index = ~index;
            else { while (index < _items.Count && comparer.Compare(_items[index], value) <= 0) index++; }
            _items.Insert(index, value);
        }
    }
    public int TrimToMaximum(int maximum)
    {
        int removed = Math.Max(0, _items.Count - maximum);
        if (removed > 0) _items.RemoveRange(0, removed);
        return removed;
    }
    public IReadOnlyList<T> RemoveOldestToMaximum(int maximum)
    {
        int removed = Math.Max(0, _items.Count - maximum);
        if (removed == 0) return [];
        var result = _items.Take(removed).ToArray();
        _items.RemoveRange(0, removed);
        return result;
    }
    public T[] Snapshot() { MaterializationCount++; return _items.ToArray(); }
}
