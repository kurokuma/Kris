using System.Security.Cryptography;
using System.Text;

namespace MRTW.Core;

/// <summary>Creates portable, bounded process and major-event graphs without resolving or executing anything.</summary>
public static class ProcessTreeGraphBuilder
{
    public const int MaxNodes = 512;
    public const int MaxEventNodes = 256;
    public const int MaxEdges = 1024;

    public static ProcessTreeGraph Build(IReadOnlyList<ProcessNode> processes, IReadOnlyList<TimelineEvent> events)
    {
        processes ??= [];
        events ??= [];
        var notes = new List<string>();
        var nodes = BuildProcessNodes(processes, notes).Take(MaxNodes).ToArray();
        if (processes.Count > nodes.Length) notes.Add($"Truncated process tree at {MaxNodes} nodes; omitted {processes.Count - nodes.Length}.");

        var severities = nodes.ToDictionary(n => n.Id, n => SeverityFor(n.Process, processes, events));
        var edges = new List<GraphEdge>();
        var parentByChild = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var child in nodes)
        {
            if (child.Process.ParentPid is not int parentPid) continue;
            var candidates = nodes.Where(p => p.Process.Pid == parentPid && p.Id != child.Id && p.Process.StartTime <= child.Process.StartTime).ToArray();
            if (candidates.Length != 1) { notes.Add(candidates.Length == 0 ? $"Missing parent for PID {child.Process.Pid} (parent PID {parentPid})." : $"Ambiguous parent PID {parentPid} for PID {child.Process.Pid}; edge omitted."); continue; }
            var parent = candidates[0];
            if (CreatesCycle(parent.Id, child.Id, parentByChild)) { notes.Add($"Cycle involving PID {child.Process.Pid} and parent PID {parentPid}; edge omitted."); continue; }
            if (!TryAddEdge(edges, new(parent.Id, child.Id), notes)) break;
            parentByChild[child.Id] = parent.Id;
        }

        int resolvableMajorCount = events.Count(e => IsMajorEvent(e) && ResolveProcess(e, nodes) is not null);
        var eventNodes = BuildEventNodes(events, nodes, notes).Take(MaxEventNodes).ToArray();
        if (resolvableMajorCount > eventNodes.Length) notes.Add($"Truncated major event chain at {MaxEventNodes} nodes; omitted {resolvableMajorCount - eventNodes.Length}.");
        var lastEventByProcess = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var item in eventNodes)
        {
            if (!TryAddEdge(edges, new(item.ProcessNode.Id, item.Id), notes)) break;
            if (lastEventByProcess.TryGetValue(item.ProcessNode.Id, out string? previous) && !TryAddEdge(edges, new(previous, item.Id), notes)) break;
            lastEventByProcess[item.ProcessNode.Id] = item.Id;
        }

        return new ProcessTreeGraph(BuildMermaid(nodes, eventNodes, edges, severities, notes), BuildDot(nodes, eventNodes, edges, severities, notes), notes, nodes.Length, edges.Count, eventNodes.Length);
    }

    private static IEnumerable<GraphNode> BuildProcessNodes(IReadOnlyList<ProcessNode> processes, ICollection<string> notes)
    {
        var candidates = processes.Select(p => new ProcessCandidate(p, ProcessKey(p), ContentHash(ProcessContent(p))))
            .OrderBy(p => p.Process.StartTime).ThenBy(p => p.Process.Pid).ThenBy(p => p.Process.Name, StringComparer.Ordinal).ThenBy(p => p.Process.ProcessGuid, StringComparer.Ordinal).ThenBy(p => p.ContentHash, StringComparer.Ordinal).ToArray();
        foreach (var group in candidates.GroupBy(p => p.Key, StringComparer.Ordinal))
        {
            if (group.Count() > 1 && group.Key.StartsWith("guid:", StringComparison.Ordinal)) notes.Add($"Duplicate process GUID observed {group.Count()} times; distinct node IDs assigned.");
            int ordinal = 0;
            foreach (var item in group) yield return new GraphNode(item.Process, Id("process:" + item.Key + ":" + ordinal++));
        }
    }

    private static IEnumerable<EventGraphNode> BuildEventNodes(IReadOnlyList<TimelineEvent> events, IReadOnlyList<GraphNode> processes, ICollection<string> notes)
    {
        int unresolved = 0;
        var candidates = events.Where(IsMajorEvent).OrderBy(e => e.Time).ThenBy(e => e.Id).ThenBy(e => e.ProcessGuid, StringComparer.Ordinal).ThenBy(e => e.Pid).ThenBy(e => e.Category).ThenBy(e => e.Action, StringComparer.Ordinal)
            .Select(e => (Event: e, Process: ResolveProcess(e, processes))).Where(x => x.Process is not null).Select(x => new EventCandidate(x.Event, x.Process!, EventKey(x.Event), ContentHash(EventContent(x.Event)))).ToArray();
        unresolved = events.Count(IsMajorEvent) - candidates.Length;
        if (unresolved > 0) notes.Add($"Omitted {unresolved} major event nodes without an unambiguous process association.");
        foreach (var group in candidates.GroupBy(c => c.Key, StringComparer.Ordinal))
        {
            int ordinal = 0;
            foreach (var item in group.OrderBy(c => c.ContentHash, StringComparer.Ordinal)) yield return new EventGraphNode(item.Event, item.Process, Id("event:" + item.Key + ":" + ordinal++));
        }
    }

    private static bool IsMajorEvent(TimelineEvent item) => item.Severity is EventSeverity.Critical or EventSeverity.High || item.Category is EventCategory.Process or EventCategory.Behavior;
    private static GraphNode? ResolveProcess(TimelineEvent item, IReadOnlyList<GraphNode> processes)
    {
        var byGuid = !string.IsNullOrWhiteSpace(item.ProcessGuid) ? processes.Where(p => string.Equals(p.Process.ProcessGuid, item.ProcessGuid, StringComparison.Ordinal)).ToArray() : [];
        if (byGuid.Length == 1) return byGuid[0];
        var byPid = processes.Where(p => p.Process.Pid == item.Pid).ToArray();
        return byPid.Length == 1 ? byPid[0] : null;
    }
    private static bool TryAddEdge(ICollection<GraphEdge> edges, GraphEdge edge, ICollection<string> notes)
    {
        if (edges.Count >= MaxEdges) { if (!notes.Any(n => n.StartsWith("Truncated process tree at " + MaxEdges, StringComparison.Ordinal))) notes.Add($"Truncated process tree at {MaxEdges} edges."); return false; }
        edges.Add(edge); return true;
    }
    private static bool CreatesCycle(string parent, string child, IReadOnlyDictionary<string, string> parentByChild)
    {
        for (string? current = parent; current is not null; parentByChild.TryGetValue(current, out current)) if (string.Equals(current, child, StringComparison.Ordinal)) return true;
        return false;
    }
    private static EventSeverity SeverityFor(ProcessNode process, IReadOnlyList<ProcessNode> all, IReadOnlyList<TimelineEvent> events)
    {
        IEnumerable<TimelineEvent> matched = !string.IsNullOrWhiteSpace(process.ProcessGuid) && all.Count(p => p.ProcessGuid == process.ProcessGuid) == 1 ? events.Where(e => string.Equals(e.ProcessGuid, process.ProcessGuid, StringComparison.Ordinal)) : all.Count(p => p.Pid == process.Pid) == 1 ? events.Where(e => e.Pid == process.Pid) : [];
        return (EventSeverity)matched.Select(e => (int)e.Severity).DefaultIfEmpty((int)EventSeverity.Informational).Min();
    }

    private static string BuildMermaid(IEnumerable<GraphNode> nodes, IEnumerable<EventGraphNode> eventNodes, IEnumerable<GraphEdge> edges, IReadOnlyDictionary<string, EventSeverity> severities, IEnumerable<string> notes)
    {
        var sb = new StringBuilder("%% MRTW offline process and major-event graph\n");
        foreach (string note in notes) sb.Append("%% ").Append(MermaidEscape(note)).Append('\n');
        sb.AppendLine("flowchart TD");
        foreach (var node in nodes) sb.Append("    ").Append(node.Id).Append("[\"").Append(MermaidEscape(ProcessLabel(node.Process, severities[node.Id]))).Append("\"]\n");
        foreach (var node in eventNodes) sb.Append("    ").Append(node.Id).Append("([\"").Append(MermaidEscape(EventLabel(node.Event))).Append("\"])\n");
        foreach (var edge in edges) sb.Append("    ").Append(edge.Source).Append(" --> ").Append(edge.Target).Append('\n');
        sb.AppendLine("    classDef critical fill:#5c1f1f,stroke:#ff7b42,color:#fff"); sb.AppendLine("    classDef high fill:#4d2c1d,stroke:#ff9a5a,color:#fff"); sb.AppendLine("    classDef medium fill:#4d421b,stroke:#ffc947,color:#fff"); sb.AppendLine("    classDef low fill:#173d5c,stroke:#58a6ff,color:#fff"); sb.AppendLine("    classDef informational fill:#26384f,stroke:#9dc3e6,color:#fff"); sb.AppendLine("    classDef event fill:#182434,stroke:#93a4b8,color:#fff");
        foreach (var node in nodes) sb.Append("    class ").Append(node.Id).Append(' ').Append(SeverityClass(severities[node.Id])).Append('\n');
        foreach (var node in eventNodes) sb.Append("    class ").Append(node.Id).Append(" event\n");
        return sb.ToString();
    }
    private static string BuildDot(IEnumerable<GraphNode> nodes, IEnumerable<EventGraphNode> eventNodes, IEnumerable<GraphEdge> edges, IReadOnlyDictionary<string, EventSeverity> severities, IEnumerable<string> notes)
    {
        var sb = new StringBuilder("digraph process_tree {\n  rankdir=TB;\n  node [shape=box, style=filled, fontname=Arial];\n");
        foreach (string note in notes) sb.Append("  // ").Append(DotComment(note)).Append('\n');
        foreach (var node in nodes) sb.Append("  ").Append(node.Id).Append(" [label=\"").Append(DotEscape(ProcessLabel(node.Process, severities[node.Id]))).Append("\", fillcolor=\"").Append(DotColor(severities[node.Id])).Append("\"];\n");
        foreach (var node in eventNodes) sb.Append("  ").Append(node.Id).Append(" [shape=ellipse, label=\"").Append(DotEscape(EventLabel(node.Event))).Append("\", fillcolor=\"#182434\"];\n");
        foreach (var edge in edges) sb.Append("  ").Append(edge.Source).Append(" -> ").Append(edge.Target).Append(";\n");
        return sb.AppendLine("}").ToString();
    }

    private static string ProcessKey(ProcessNode p) => !string.IsNullOrWhiteSpace(p.ProcessGuid) ? "guid:" + p.ProcessGuid : "fallback:" + p.Pid + ":" + p.StartTime.UtcTicks + ":" + p.Name + ":" + (p.ParentPid?.ToString() ?? "none") + ":" + ContentHash(ProcessContent(p));
    private static string EventKey(TimelineEvent e) => e.Id + ":" + e.Time.Ticks + ":" + e.ProcessGuid + ":" + e.Pid + ":" + e.Category + ":" + e.Action;
    private static string ProcessContent(ProcessNode p) => string.Join("\u001f", p.Pid, p.ParentPid, p.ProcessGuid, p.Name, p.CommandLine, p.ImagePath, p.StartTime.UtcTicks, p.EndTime?.UtcTicks, p.EventCount, p.NetworkCount, p.FileCount, p.RegistryCount);
    private static string EventContent(TimelineEvent e) => string.Join("\u001f", e.Id, e.Time.Ticks, e.ProcessGuid, e.Pid, e.Category, e.Action, e.Source, e.Severity);
    private static string ContentHash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private static string Id(string value) => "n_" + ContentHash(value)[..16];
    private static string ProcessLabel(ProcessNode process, EventSeverity severity) => $"{Bounded(process.Name, 128)} (PID {process.Pid})\\n{severity}";
    private static string EventLabel(TimelineEvent item) => $"Event {item.Id}: {item.Category} / {item.Severity}";
    private static string Bounded(string value, int max) => value.Length <= max ? value : value[..max] + "...";
    private static string SeverityClass(EventSeverity severity) => severity.ToString().ToLowerInvariant();
    private static string DotColor(EventSeverity severity) => severity switch { EventSeverity.Critical => "#5c1f1f", EventSeverity.High => "#4d2c1d", EventSeverity.Medium => "#4d421b", EventSeverity.Low => "#173d5c", _ => "#26384f" };
    private static string MermaidEscape(string value) => value.Replace("&", "&amp;", StringComparison.Ordinal).Replace("\"", "&quot;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal).Replace(">", "&gt;", StringComparison.Ordinal).Replace("[", "&#91;", StringComparison.Ordinal).Replace("]", "&#93;", StringComparison.Ordinal).Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal).Replace("\\n", "&#10;", StringComparison.Ordinal);
    private static string DotEscape(string value) => value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal).Replace("\r", "", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
    private static string DotComment(string value) => value.Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);
    private sealed record ProcessCandidate(ProcessNode Process, string Key, string ContentHash);
    private sealed record EventCandidate(TimelineEvent Event, GraphNode Process, string Key, string ContentHash);
    private sealed record GraphNode(ProcessNode Process, string Id);
    private sealed record EventGraphNode(TimelineEvent Event, GraphNode ProcessNode, string Id);
    private sealed record GraphEdge(string Source, string Target);
}

public sealed record ProcessTreeGraph(string Mermaid, string Dot, IReadOnlyList<string> Notes, int NodeCount, int EdgeCount, int EventNodeCount = 0);
