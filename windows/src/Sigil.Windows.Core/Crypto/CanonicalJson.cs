using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sigil.Windows.Core.Crypto;

/// <summary>
/// RFC 8785 (JCS) canonical JSON serialization for signature verification.
/// Per api/wire-protocol.md section 5.1 - payloads MUST be canonicalized before signing.
/// </summary>
[RequiresUnreferencedCode("CanonicalJson uses reflection-based JSON serialization for protocol compliance")]
[RequiresDynamicCode("CanonicalJson requires runtime code generation for JSON serialization")]
public static class CanonicalJson
{
    private static readonly JsonSerializerOptions CanonicalOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never
    };

    /// <summary>
    /// Serializes object to RFC 8785 canonical JSON.
    /// - Sorted keys (lexicographically)
    /// - No whitespace
    /// - Minimal encoding (no escaped Unicode)
    /// </summary>
    public static string Serialize(object obj)
    {
        var json = JsonSerializer.Serialize(obj, CanonicalOptions);
        var node = JsonNode.Parse(json);
        return CanonicalizeNode(node);
    }

    /// <summary>
    /// Canonicalizes a JsonNode per RFC 8785.
    /// </summary>
    private static string CanonicalizeNode(JsonNode? node)
    {
        if (node == null)
        {
            return "null";
        }

        return node switch
        {
            JsonObject obj => CanonicalizeObject(obj),
            JsonArray arr => CanonicalizeArray(arr),
            JsonValue val => CanonicalizeValue(val),
            _ => throw new NotSupportedException($"Unsupported JsonNode type: {node.GetType()}")
        };
    }

    private static string CanonicalizeObject(JsonObject obj)
    {
        var sb = new StringBuilder();
        sb.Append('{');

        var sortedKeys = obj.Select(kv => kv.Key).OrderBy(k => k, StringComparer.Ordinal).ToArray();
        var first = true;

        foreach (var key in sortedKeys)
        {
            if (!first)
            {
                sb.Append(',');
            }

            first = false;

            sb.Append('"');
            sb.Append(key);
            sb.Append('"');
            sb.Append(':');
            sb.Append(CanonicalizeNode(obj[key]));
        }

        sb.Append('}');
        return sb.ToString();
    }

    private static string CanonicalizeArray(JsonArray arr)
    {
        var sb = new StringBuilder();
        sb.Append('[');

        var first = true;
        foreach (var item in arr)
        {
            if (!first)
            {
                sb.Append(',');
            }

            first = false;
            sb.Append(CanonicalizeNode(item));
        }

        sb.Append(']');
        return sb.ToString();
    }

    private static string CanonicalizeValue(JsonValue val)
    {
        if (val.TryGetValue<string>(out var str))
        {
            return JsonSerializer.Serialize(str);
        }

        if (val.TryGetValue<long>(out var l))
        {
            return l.ToString(CultureInfo.InvariantCulture);
        }

        if (val.TryGetValue<int>(out var i))
        {
            return i.ToString(CultureInfo.InvariantCulture);
        }

        if (val.TryGetValue<bool>(out var b))
        {
            return b ? "true" : "false";
        }

        if (val.TryGetValue<double>(out var d))
        {
            return d.ToString("G17", CultureInfo.InvariantCulture);
        }

        return val.ToJsonString();
    }
}
