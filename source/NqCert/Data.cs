using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;

namespace NqCert;

public class DataItem
{
    [Key, MaxLength(64)] public string Key { get; set; } = "";
    public string Json { get; set; } = "null";
    [ConcurrencyCheck] public int Version { get; set; }
    [MaxLength(60)] public string UpdatedBy { get; set; } = "";
    public DateTime UpdatedAt { get; set; }
}

public class AppUser
{
    public int Id { get; set; }
    [MaxLength(40)] public string Username { get; set; } = "";
    [MaxLength(100)] public string Name { get; set; } = "";
    public int RoleId { get; set; }
    public int? AuditorId { get; set; }
    public bool Active { get; set; } = true;
    [MaxLength(200)] public string PasswordHash { get; set; } = "";
    public int Fails { get; set; }
    public DateTime? LockUntil { get; set; }
    public DateTime? LastLogin { get; set; }
    public DateTime Created { get; set; } = DateTime.UtcNow;
    [MaxLength(40)] public string Stamp { get; set; } = Guid.NewGuid().ToString("N");
}

public class LogEntry
{
    public long Id { get; set; }
    public DateTime At { get; set; }
    [MaxLength(60)] public string User { get; set; } = "";
    [MaxLength(500)] public string Action { get; set; } = "";
    [MaxLength(60)] public string Ip { get; set; } = "";
}

public class AppDb(DbContextOptions<AppDb> o) : DbContext(o)
{
    public DbSet<DataItem> Items => Set<DataItem>();
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<LogEntry> Logs => Set<LogEntry>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<DataItem>().ToTable("NqItems");
        b.Entity<AppUser>().ToTable("NqUsers").HasIndex(x => x.Username).IsUnique();
        b.Entity<LogEntry>().ToTable("NqLog").HasIndex(x => x.At);
    }

    public void Log(string user, string action, string ip = "") =>
        Logs.Add(new LogEntry { At = DateTime.UtcNow, User = Cut(user, 60), Action = Cut(action, 500), Ip = Cut(ip, 60) });

    static string Cut(string s, int n) => s.Length > n ? s[..n] : s;
}

/// إعداد قاعدة البيانات: من appsettings (ConnectionStrings:Default) أو من App_Data/db.json الذي تكتبه شاشة الإعداد الأولى
public class DbConfig
{
    public string Provider { get; set; } = "";
    public string Conn { get; set; } = "";
    public string Dir { get; set; } = "";
    public bool Configured => !string.IsNullOrWhiteSpace(Conn);

    public static DbConfig Load(string dir, IConfiguration cfg)
    {
        var c = new DbConfig { Dir = dir };
        var cs = cfg.GetConnectionString("Default");
        if (!string.IsNullOrWhiteSpace(cs)) { c.Provider = cfg["DbProvider"] ?? "sqlserver"; c.Conn = cs; return c; }
        var f = Path.Combine(dir, "db.json");
        if (File.Exists(f))
        {
            var j = JsonNode.Parse(File.ReadAllText(f));
            c.Provider = (string?)j?["provider"] ?? "sqlserver";
            c.Conn = (string?)j?["connectionString"] ?? "";
        }
        return c;
    }

    public void Apply(DbContextOptionsBuilder o)
    {
        if (!Configured) { o.UseSqlite("Data Source=:memory:"); return; }
        if (Provider == "sqlite") o.UseSqlite(Conn); else o.UseSqlServer(Conn);
    }

    public void Save() => File.WriteAllText(Path.Combine(Dir, "db.json"),
        JsonSerializer.Serialize(new { provider = Provider, connectionString = Conn }));
}

public static class Pw
{
    public static string Hash(string p)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var h = Rfc2898DeriveBytes.Pbkdf2(p, salt, 100000, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2$100000${Convert.ToBase64String(salt)}${Convert.ToBase64String(h)}";
    }

    public static bool Verify(string p, string stored)
    {
        try
        {
            var parts = stored.Split('$');
            if (parts.Length != 4 || parts[0] != "pbkdf2") return false;
            var salt = Convert.FromBase64String(parts[2]);
            var h = Convert.FromBase64String(parts[3]);
            var c = Rfc2898DeriveBytes.Pbkdf2(p, salt, int.Parse(parts[1]), HashAlgorithmName.SHA256, h.Length);
            return CryptographicOperations.FixedTimeEquals(c, h);
        }
        catch { return false; }
    }
}

/// حساب الطوارئ: ثابت داخل الكود (مخزن كـ hash فقط) ولا يظهر في قاعدة البيانات
public static class Emergency
{
    public const string User = "erpadmin";
    public const string Hash = "pbkdf2$100000$EShVtHU0cnxRTBKz64LK6A==$E0J4JI8W9Bo/Gd4DgIJ/l394HbfPDUvFph4O2iIE2iM=";
}

public record Me(int Id, bool Power, string Username, string Name, int RoleId, int? AuditorId);

public static class Perm
{
    public static readonly string[] Modules = ["companies", "auditors", "certificates", "standards", "audits", "indicators", "invoices", "tasks", "queries", "training", "settings", "users"];

    /// كل مفتاح بيانات ومين يقدر يعدّله (أي وحدة من القائمة)
    public static readonly Dictionary<string, string[]> KeyMods = new()
    {
        ["standards"] = ["standards"],
        ["companies"] = ["companies", "settings"],
        ["auditors"] = ["auditors", "settings"],
        ["certificates"] = ["certificates", "audits", "settings"],
        ["audits"] = ["audits", "settings"],
        ["history"] = ["audits", "settings"],
        ["expenses"] = ["audits"],
        ["team"] = ["audits"],
        ["students"] = ["training"], ["courses"] = ["training"], ["sessions"] = ["training"],
        ["invoices"] = ["invoices", "audits"],
        ["tasks"] = ["tasks"],
        ["queries"] = ["queries", "companies"],
        ["contacts"] = ["companies"], ["sites"] = ["companies"],
        ["docs"] = ["companies", "certificates"],
        ["plans"] = ["certificates", "audits", "settings"],
        ["scopes"] = ["certificates"],
        ["numbering"] = ["settings"], ["lists"] = ["settings"], ["ui"] = ["settings"],
        ["usedNos"] = ["certificates", "audits"],
        ["auditorCategories"] = ["auditors"], ["auditorScopes"] = ["auditors"], ["auditorCV"] = ["auditors"],
        ["auditorRoles"] = ["auditors"], ["auditorDocs"] = ["auditors"], ["auditorCerts"] = ["auditors"],
        ["roles"] = ["users"],
    };

    static readonly Dictionary<string, string> Labels = new()
    {
        ["standards"] = "المعايير", ["companies"] = "الشركات", ["auditors"] = "المراجعون", ["certificates"] = "الشهادات",
        ["audits"] = "المراجعات", ["history"] = "سجل الحالات", ["expenses"] = "المصروفات", ["team"] = "فرق المراجعة",
        ["students"] = "المتدربون", ["courses"] = "الدورات", ["sessions"] = "الدورات المنفذة", ["invoices"] = "الفوترة",
        ["tasks"] = "المهام", ["queries"] = "الاستفسارات", ["contacts"] = "جهات الاتصال", ["sites"] = "المواقع",
        ["docs"] = "المستندات", ["plans"] = "خطط المراجعات", ["scopes"] = "النطاقات", ["numbering"] = "ترقيم الشهادات",
        ["lists"] = "قوائم الإعدادات", ["ui"] = "المظهر", ["usedNos"] = "أرقام الشهادات", ["roles"] = "الأدوار والصلاحيات",
    };
    public static string Label(string k) => Labels.TryGetValue(k, out var l) ? l : k.StartsWith("auditor") ? "ملفات المراجعين" : k;

    public static JsonArray DefaultRoles()
    {
        JsonObject P(Dictionary<string, string> l)
        {
            var o = new JsonObject();
            foreach (var m in Modules)
            {
                var x = l.TryGetValue(m, out var v) ? v : (l.TryGetValue("*", out var s) ? s : "");
                o[m] = new JsonObject { ["view"] = x != "", ["edit"] = x == "e" };
            }
            return o;
        }
        return new JsonArray(
            new JsonObject { ["id"] = 1, ["name"] = "مدير النظام", ["all"] = true, ["locked"] = true, ["perms"] = new JsonObject() },
            new JsonObject { ["id"] = 2, ["name"] = "مدير الجودة", ["perms"] = P(new() { ["*"] = "e", ["settings"] = "v", ["users"] = "" }) },
            new JsonObject { ["id"] = 3, ["name"] = "مراجع", ["perms"] = P(new() { ["companies"] = "v", ["auditors"] = "v", ["certificates"] = "v", ["standards"] = "v", ["audits"] = "e", ["indicators"] = "v", ["tasks"] = "e", ["queries"] = "e", ["training"] = "v" }) },
            new JsonObject { ["id"] = 4, ["name"] = "محاسب", ["perms"] = P(new() { ["companies"] = "v", ["certificates"] = "v", ["audits"] = "v", ["indicators"] = "v", ["invoices"] = "e" }) },
            new JsonObject { ["id"] = 5, ["name"] = "مشاهد فقط", ["perms"] = P(new() { ["*"] = "v", ["settings"] = "", ["users"] = "" }) });
    }

    public static JsonArray Roles(AppDb db)
    {
        var it = db.Items.AsNoTracking().FirstOrDefault(i => i.Key == "roles");
        if (it == null) return DefaultRoles();
        try { return JsonNode.Parse(it.Json) as JsonArray ?? DefaultRoles(); } catch { return DefaultRoles(); }
    }

    public static JsonObject? Role(JsonArray roles, int id) =>
        roles.OfType<JsonObject>().FirstOrDefault(r => Int(r["id"]) == id);

    public static int? Int(JsonNode? n) { try { return n?.GetValue<int>(); } catch { try { return (int?)n?.GetValue<double>(); } catch { return null; } } }
    static bool Bool(JsonNode? n) { try { return n?.GetValue<bool>() == true; } catch { return false; } }

    public static bool IsFull(JsonArray roles, int roleId) => Bool(Role(roles, roleId)?["all"]);
    public static bool IsFull(JsonArray roles, Me me) => me.Power || IsFull(roles, me.RoleId);

    public static bool Can(Me me, JsonArray roles, string m, bool edit)
    {
        if (me.Power) return true;
        var r = Role(roles, me.RoleId);
        if (r == null) return false;
        if (Bool(r["all"])) return true;
        var p = r["perms"]?[m];
        if (p == null) return false;
        bool e = Bool(p["edit"]), v = Bool(p["view"]);
        return edit ? e : (v || e);
    }

    /// تنظيف كل النصوص من رموز HTML قبل الحفظ
    public static JsonNode? Clean(JsonNode? n) => n switch
    {
        JsonObject o => new JsonObject(o.Select(kv => KeyValuePair.Create(Strip(kv.Key), Clean(kv.Value)))),
        JsonArray a => new JsonArray(a.Select(Clean).ToArray()),
        JsonValue v when v.TryGetValue<string>(out var s) => JsonValue.Create(Strip(s)),
        JsonValue v => v.DeepClone(),
        _ => null
    };
    public static string Strip(string s) => s.IndexOfAny(['<', '>', '"', '`']) < 0 ? s : new string(s.Where(c => c is not ('<' or '>' or '"' or '`')).ToArray());
}

public static class Seed
{
    public static void Run(AppDb db)
    {
        db.Database.EnsureCreated();
        if (!db.Items.Any(i => i.Key == "roles"))
            db.Items.Add(new DataItem { Key = "roles", Json = Perm.DefaultRoles().ToJsonString(), Version = 1, UpdatedBy = "system", UpdatedAt = DateTime.UtcNow });
        if (!db.Users.Any())
        {
            db.Users.Add(new AppUser { Username = "admin", Name = "مدير النظام", RoleId = 1, PasswordHash = Pw.Hash("admin") });
            db.Log("system", "تهيئة النظام وإنشاء حساب admin");
        }
        var old = DateTime.UtcNow.AddYears(-2);
        db.Logs.Where(l => l.At < old).ExecuteDelete();
        db.SaveChanges();
    }
}
