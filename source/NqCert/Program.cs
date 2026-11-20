using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using NqCert;

var builder = WebApplication.CreateBuilder(args);
var dataDir = Path.Combine(builder.Environment.ContentRootPath, "App_Data");
try { Directory.CreateDirectory(Path.Combine(dataDir, "keys")); }
catch { dataDir = Path.Combine(Path.GetTempPath(), "NqCert_App_Data"); Directory.CreateDirectory(Path.Combine(dataDir, "keys")); }
var dbcfg = DbConfig.Load(dataDir, builder.Configuration);

builder.Services.AddSingleton(dbcfg);
builder.Services.AddDbContext<AppDb>((sp, o) => sp.GetRequiredService<DbConfig>().Apply(o));
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDir, "keys"))).SetApplicationName("NqCert");
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o =>
{
    o.Cookie.Name = "nq_auth";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    o.ExpireTimeSpan = TimeSpan.FromHours(10);
    o.SlidingExpiration = true;
    o.Events.OnRedirectToLogin = c => { c.Response.StatusCode = 401; return Task.CompletedTask; };
    o.Events.OnRedirectToAccessDenied = c => { c.Response.StatusCode = 403; return Task.CompletedTask; };
    o.Events.OnValidatePrincipal = async c =>
    {
        var uid = c.Principal?.FindFirstValue("uid");
        if (uid == "0") return;
        var db = c.HttpContext.RequestServices.GetRequiredService<AppDb>();
        var u = int.TryParse(uid, out var id) ? await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id) : null;
        if (u == null || !u.Active || u.Stamp != c.Principal!.FindFirstValue("stamp"))
        {
            c.RejectPrincipal();
            await c.HttpContext.SignOutAsync();
        }
    };
});
builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.AddPolicy("login", ctx => RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "x",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1) }));
    o.AddPolicy("public", ctx => RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "x",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 60, Window = TimeSpan.FromMinutes(1) }));
});
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    o.SerializerOptions.PropertyNameCaseInsensitive = true;
    o.SerializerOptions.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
});

var app = builder.Build();

if (dbcfg.Configured)
{
    try { using var s = app.Services.CreateScope(); Seed.Run(s.ServiceProvider.GetRequiredService<AppDb>()); }
    catch (Exception ex) { app.Logger.LogError(ex, "Database init failed"); }
}

app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "DENY";
    h["Referrer-Policy"] = "same-origin";
    var path = ctx.Request.Path.Value ?? "";
    if (path.StartsWith("/api", StringComparison.OrdinalIgnoreCase))
    {
        h["Cache-Control"] = "no-store";
        if (!HttpMethods.IsGet(ctx.Request.Method) && !ctx.Request.Headers.ContainsKey("X-NQ"))
        { ctx.Response.StatusCode = 400; return; }
        if (!dbcfg.Configured && path != "/api/status" && path != "/api/setup")
        { ctx.Response.StatusCode = 503; await ctx.Response.WriteAsJsonAsync(new { setup = true }); return; }
    }
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions { OnPrepareResponse = c => c.Context.Response.Headers.CacheControl = "no-cache" });
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// ---------------- helpers ----------------
static IResult Err(string msg, int code = 400) => Results.Json(new { error = msg }, statusCode: code);
static string Ip(HttpContext c) => c.Connection.RemoteIpAddress?.ToString() ?? "";
static string Iso(DateTime? d) => d == null ? "" : DateTime.SpecifyKind(d.Value, DateTimeKind.Utc).ToString("o");

static async Task<Me?> GetMe(HttpContext ctx, AppDb db)
{
    if (ctx.User.Identity?.IsAuthenticated != true) return null;
    var uid = ctx.User.FindFirstValue("uid");
    if (uid == "0") return new Me(0, true, Emergency.User, "مدير الطوارئ", 0, null);
    if (!int.TryParse(uid, out var id)) return null;
    var u = await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id);
    return u == null || !u.Active ? null : new Me(u.Id, false, u.Username, u.Name, u.RoleId, u.AuditorId);
}

static Task SignIn(HttpContext ctx, string uid, string stamp, bool defaultPw) =>
    ctx.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity(new[]
    {
        new Claim("uid", uid), new Claim("stamp", stamp), new Claim("dpw", defaultPw ? "1" : "0")
    }, CookieAuthenticationDefaults.AuthenticationScheme)), new AuthenticationProperties { IsPersistent = false });

static object UserDto(AppUser u) => new
{
    u.Id, u.Username, u.Name, u.RoleId, u.AuditorId, u.Active,
    lastLogin = Iso(u.LastLogin), created = Iso(u.Created),
    locked = u.LockUntil > DateTime.UtcNow
};

static int ActiveFullAdmins(AppDb db, JsonArray roles) =>
    db.Users.AsNoTracking().Where(x => x.Active).AsEnumerable().Count(x => Perm.IsFull(roles, x.RoleId));

static JsonObject ItemsJson(IEnumerable<DataItem> items)
{
    var o = new JsonObject();
    foreach (var it in items)
    {
        JsonNode? d; try { d = JsonNode.Parse(it.Json); } catch { d = null; }
        o[it.Key] = new JsonObject { ["data"] = d, ["version"] = it.Version };
    }
    return o;
}

// ---------------- setup ----------------
app.MapGet("/api/status", () => Results.Ok(new { configured = dbcfg.Configured, version = "1.0" }));

app.MapPost("/api/setup", (SetupReq r) =>
{
    if (dbcfg.Configured) return Err("النظام مُعد بالفعل", 409);
    if (!Pw.Verify(r.EmergencyPassword ?? "", Emergency.Hash)) return Err("كلمة مرور الطوارئ غير صحيحة", 401);
    var provider = r.Provider == "sqlite" ? "sqlite" : "sqlserver";
    var conn = provider == "sqlite" ? $"Data Source={Path.Combine(dataDir, "nq.db")}" : (r.ConnectionString ?? "").Trim();
    if (conn == "") return Err("أدخل نص الاتصال بقاعدة البيانات (Connection string)");
    var test = new DbConfig { Provider = provider, Conn = conn, Dir = dataDir };
    try
    {
        var ob = new DbContextOptionsBuilder<AppDb>(); test.Apply(ob);
        using var db = new AppDb(ob.Options);
        Seed.Run(db);
    }
    catch (Exception ex) { return Err("تعذّر الاتصال بقاعدة البيانات: " + ex.GetBaseException().Message); }
    try { test.Save(); }
    catch (Exception ex) { return Err("تم الاتصال لكن تعذّر حفظ الإعداد في App_Data: " + ex.Message + " — ارفع ملف App_Data/db.json يدويًا"); }
    dbcfg.Provider = provider; dbcfg.Conn = conn;
    return Results.Ok(new { ok = true });
}).RequireRateLimiting("login");

// ---------------- auth ----------------
app.MapPost("/api/login", async (LoginReq r, HttpContext ctx, AppDb db) =>
{
    var u = (r.Username ?? "").Trim().ToLowerInvariant();
    var p = r.Password ?? "";
    var ip = Ip(ctx);
    const string bad = "بيانات الدخول غير صحيحة";
    if (u == "" || p == "") return Err("أدخل اسم المستخدم وكلمة المرور");
    if (u == Emergency.User)
    {
        if (Pw.Verify(p, Emergency.Hash))
        {
            await SignIn(ctx, "0", "power", false);
            db.Log(u, "دخول طوارئ", ip); await db.SaveChangesAsync();
            return Results.Ok(new { ok = true });
        }
        db.Log(u, "محاولة دخول طوارئ فاشلة", ip); await db.SaveChangesAsync();
        return Err(bad, 401);
    }
    var x = await db.Users.FirstOrDefaultAsync(z => z.Username == u);
    if (x == null) { Pw.Verify(p, Emergency.Hash); db.Log(u, "محاولة دخول فاشلة", ip); await db.SaveChangesAsync(); return Err(bad, 401); }
    if (!x.Active) return Err("الحساب موقوف — تواصل مع مدير النظام", 403);
    if (x.LockUntil > DateTime.UtcNow)
        return Err($"الحساب مقفول مؤقتًا بسبب محاولات خاطئة — حاول بعد {Math.Ceiling((x.LockUntil.Value - DateTime.UtcNow).TotalMinutes)} دقيقة", 423);
    if (!Pw.Verify(p, x.PasswordHash))
    {
        x.Fails++;
        if (x.Fails >= 5) { x.LockUntil = DateTime.UtcNow.AddMinutes(10); x.Fails = 0; db.Log(u, "قفل الحساب 10 دقائق بعد 5 محاولات خاطئة", ip); }
        else db.Log(u, "محاولة دخول فاشلة", ip);
        await db.SaveChangesAsync();
        return Err(bad, 401);
    }
    x.Fails = 0; x.LockUntil = null; x.LastLogin = DateTime.UtcNow;
    db.Log(u, "تسجيل دخول", ip);
    await db.SaveChangesAsync();
    await SignIn(ctx, x.Id.ToString(), x.Stamp, p == "admin");
    return Results.Ok(new { ok = true });
}).RequireRateLimiting("login");

app.MapPost("/api/logout", async (HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me != null) { db.Log(me.Username, "تسجيل خروج", Ip(ctx)); await db.SaveChangesAsync(); }
    await ctx.SignOutAsync();
    return Results.Ok(new { ok = true });
});

app.MapGet("/api/me", async (HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me == null) return Results.Unauthorized();
    return Results.Ok(new
    {
        id = me.Id, username = me.Username, name = me.Name, role = me.Power ? (object)"__power" : me.RoleId,
        auditorId = me.AuditorId, power = me.Power, defaultPw = ctx.User.FindFirstValue("dpw") == "1"
    });
});

app.MapPost("/api/password", async (PwReq r, HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me == null) return Results.Unauthorized();
    if (me.Power) return Err("كلمة مرور الطوارئ ثابتة ولا تتغير من هنا");
    var u = await db.Users.FirstAsync(x => x.Id == me.Id);
    if (!Pw.Verify(r.Current ?? "", u.PasswordHash)) return Err("كلمة المرور الحالية غير صحيحة");
    if ((r.New ?? "").Length < 6) return Err("كلمة المرور الجديدة أقل من 6 أحرف");
    u.PasswordHash = Pw.Hash(r.New!); u.Stamp = Guid.NewGuid().ToString("N");
    db.Log(u.Username, "تغيير كلمة المرور", Ip(ctx));
    await db.SaveChangesAsync();
    await SignIn(ctx, u.Id.ToString(), u.Stamp, false);
    return Results.Ok(new { ok = true });
});

// ---------------- data ----------------
app.MapGet("/api/state", async (string? keys, HttpContext ctx, AppDb db) =>
{
    if (await GetMe(ctx, db) == null) return Results.Unauthorized();
    var q = db.Items.AsNoTracking();
    if (!string.IsNullOrWhiteSpace(keys)) { var ks = keys.Split(','); q = q.Where(i => ks.Contains(i.Key)); }
    return Results.Ok(new JsonObject { ["items"] = ItemsJson(await q.ToListAsync()) });
});

app.MapGet("/api/versions", async (HttpContext ctx, AppDb db) =>
{
    if (await GetMe(ctx, db) == null) return Results.Unauthorized();
    return Results.Ok(await db.Items.AsNoTracking().ToDictionaryAsync(i => i.Key, i => i.Version));
});

app.MapPost("/api/state", async (SaveReq r, HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me == null) return Results.Unauthorized();
    var changes = r.Changes ?? [];
    if (changes.Count == 0) return Results.Ok(new { versions = new Dictionary<string, int>() });
    var roles = Perm.Roles(db);
    foreach (var c in changes)
    {
        if (!Perm.KeyMods.TryGetValue(c.Key ?? "", out var mods)) return Err("بيانات غير معروفة: " + c.Key);
        if (!mods.Any(m => Perm.Can(me, roles, m, true)))
            return Results.Json(new { error = "ليس لديك صلاحية حفظ: " + Perm.Label(c.Key!), forbidden = c.Key }, statusCode: 403);
    }
    var rc = changes.FirstOrDefault(c => c.Key == "roles");
    if (rc != null)
    {
        if (rc.Data is not JsonArray nr) return Err("صيغة الأدوار غير صحيحة");
        var ids = nr.OfType<JsonObject>().Select(x => Perm.Int(x["id"])).ToList();
        if (ids.Any(i => i == null) || ids.Distinct().Count() != ids.Count) return Err("أرقام الأدوار غير صحيحة");
        if (!nr.OfType<JsonObject>().Any(x => Perm.IsFull(nr, Perm.Int(x["id"])!.Value))) return Err("لازم يفضل دور مدير نظام بكل الصلاحيات");
        var used = await db.Users.Select(u => u.RoleId).Distinct().ToListAsync();
        if (used.Any(id => !ids.Contains(id))) return Err("لا يمكن حذف دور مرتبط بمستخدمين");
        if (ActiveFullAdmins(db, nr) == 0) return Err("التعديل ده هيشيل كل مديري النظام — مرفوض");
    }

    var keys = changes.Select(c => c.Key!).ToList();
    var existing = await db.Items.Where(i => keys.Contains(i.Key)).ToDictionaryAsync(i => i.Key);
    var conflicts = new JsonObject();
    foreach (var c in changes)
    {
        existing.TryGetValue(c.Key!, out var it);
        var cur = it?.Version ?? 0;
        if (cur != c.BaseVersion) conflicts[c.Key!] = new JsonObject { ["data"] = it == null ? null : JsonNode.Parse(it.Json), ["version"] = cur };
    }
    if (conflicts.Count > 0) return Results.Json(new { conflicts }, statusCode: 409);

    var versions = new Dictionary<string, int>();
    foreach (var c in changes)
    {
        existing.TryGetValue(c.Key!, out var it);
        if (it == null) { it = new DataItem { Key = c.Key!, Version = 0 }; db.Items.Add(it); }
        it.Json = Perm.Clean(c.Data)?.ToJsonString() ?? "null";
        it.Version += 1; it.UpdatedBy = me.Username; it.UpdatedAt = DateTime.UtcNow;
        versions[c.Key!] = it.Version;
    }
    db.Log(me.Username, "تعديل: " + string.Join("، ", keys.Select(Perm.Label).Distinct()), Ip(ctx));
    try { await db.SaveChangesAsync(); }
    catch (DbUpdateException)
    {
        db.ChangeTracker.Clear();
        var now = await db.Items.AsNoTracking().Where(i => keys.Contains(i.Key)).ToListAsync();
        var cf = new JsonObject();
        foreach (var k in keys)
        {
            var it = now.FirstOrDefault(i => i.Key == k);
            cf[k] = new JsonObject { ["data"] = it == null ? null : JsonNode.Parse(it.Json), ["version"] = it?.Version ?? 0 };
        }
        return Results.Json(new { conflicts = cf }, statusCode: 409);
    }
    return Results.Ok(new { versions });
});

// ---------------- users ----------------
app.MapGet("/api/users", async (HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me == null) return Results.Unauthorized();
    if (!Perm.Can(me, Perm.Roles(db), "users", false)) return Err("ليس لديك صلاحية", 403);
    var list = await db.Users.AsNoTracking().OrderBy(u => u.Id).ToListAsync();
    return Results.Ok(list.Select(UserDto));
});

app.MapPost("/api/users", async (UserReq r, HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me == null) return Results.Unauthorized();
    var roles = Perm.Roles(db);
    if (!Perm.Can(me, roles, "users", true)) return Err("ليس لديك صلاحية", 403);
    var un = (r.Username ?? "").Trim().ToLowerInvariant();
    if (!Regex.IsMatch(un, "^[a-z0-9._-]{3,30}$")) return Err("اسم المستخدم: 3 أحرف على الأقل — حروف إنجليزية وأرقام و . _ - فقط");
    if (un == Emergency.User) return Err("هذا الاسم محجوز لحساب الطوارئ");
    if (await db.Users.AnyAsync(x => x.Id != (r.Id ?? 0) && x.Username == un)) return Err("اسم المستخدم مستخدم من قبل");
    if (Perm.Role(roles, r.RoleId) == null) return Err("الدور غير موجود");
    var pw = r.Password ?? "";
    if (r.Id == null && pw == "") return Err("أدخل كلمة المرور");
    if (pw != "" && pw.Length < 6) return Err("كلمة المرور 6 أحرف على الأقل");
    var name = Perm.Strip((r.Name ?? "").Trim());
    if (r.Id == null)
    {
        var nu = new AppUser { Username = un, Name = name, RoleId = r.RoleId, AuditorId = r.AuditorId, Active = r.Active, PasswordHash = Pw.Hash(pw) };
        db.Users.Add(nu);
        db.Log(me.Username, "إضافة المستخدم " + un, Ip(ctx));
        await db.SaveChangesAsync();
        return Results.Ok(new { ok = true, id = nu.Id });
    }
    var u = await db.Users.FirstOrDefaultAsync(x => x.Id == r.Id);
    if (u == null) return Err("المستخدم غير موجود", 404);
    if (u.Id == me.Id && !r.Active) return Err("لا يمكنك إيقاف حسابك وأنت داخل به");
    if (u.Active && Perm.IsFull(roles, u.RoleId) && (!r.Active || !Perm.IsFull(roles, r.RoleId)) && ActiveFullAdmins(db, roles) <= 1)
        return Err("لا يمكن إيقاف أو تغيير دور آخر مدير نظام");
    var revoke = pw != "" || (u.Active && !r.Active) || u.RoleId != r.RoleId || u.Username != un;
    u.Username = un; u.Name = name; u.RoleId = r.RoleId; u.AuditorId = r.AuditorId; u.Active = r.Active; u.Fails = 0; u.LockUntil = null;
    if (pw != "") u.PasswordHash = Pw.Hash(pw);
    if (revoke) u.Stamp = Guid.NewGuid().ToString("N");
    db.Log(me.Username, "تعديل المستخدم " + un + (pw != "" ? " (مع تغيير كلمة المرور)" : ""), Ip(ctx));
    await db.SaveChangesAsync();
    if (revoke && u.Id == me.Id) await SignIn(ctx, u.Id.ToString(), u.Stamp, false);
    return Results.Ok(new { ok = true, id = u.Id });
});

app.MapDelete("/api/users/{id:int}", async (int id, HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me == null) return Results.Unauthorized();
    var roles = Perm.Roles(db);
    if (!Perm.Can(me, roles, "users", true)) return Err("ليس لديك صلاحية", 403);
    if (id == me.Id) return Err("لا يمكنك حذف حسابك وأنت داخل به");
    var u = await db.Users.FirstOrDefaultAsync(x => x.Id == id);
    if (u == null) return Err("المستخدم غير موجود", 404);
    if (u.Active && Perm.IsFull(roles, u.RoleId) && ActiveFullAdmins(db, roles) <= 1) return Err("لا يمكن حذف آخر مدير نظام");
    db.Users.Remove(u);
    db.Log(me.Username, "حذف المستخدم " + u.Username, Ip(ctx));
    await db.SaveChangesAsync();
    return Results.Ok(new { ok = true });
});

app.MapGet("/api/log", async (string? q, HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me == null) return Results.Unauthorized();
    if (!Perm.Can(me, Perm.Roles(db), "users", false)) return Err("ليس لديك صلاحية", 403);
    var qq = db.Logs.AsNoTracking();
    if (!string.IsNullOrWhiteSpace(q)) qq = qq.Where(l => l.User.Contains(q) || l.Action.Contains(q));
    var rows = await qq.OrderByDescending(l => l.Id).Take(300).ToListAsync();
    return Results.Ok(rows.Select(l => new { at = Iso(l.At), user = l.User, action = l.Action, ip = l.Ip }));
});

// ---------------- backup / restore ----------------
app.MapGet("/api/backup", async (HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me == null) return Results.Unauthorized();
    if (!Perm.IsFull(Perm.Roles(db), me)) return Err("النسخ الاحتياطي لمدير النظام فقط", 403);
    var items = await db.Items.AsNoTracking().ToListAsync();
    var users = await db.Users.AsNoTracking().ToListAsync();
    db.Log(me.Username, "تصدير نسخة احتياطية", Ip(ctx)); await db.SaveChangesAsync();
    var o = new JsonObject
    {
        ["app"] = "nq-cert-server", ["v"] = 1, ["exported"] = Iso(DateTime.UtcNow),
        ["items"] = ItemsJson(items),
        ["users"] = new JsonArray(users.Select(u => (JsonNode)new JsonObject
        {
            ["username"] = u.Username, ["name"] = u.Name, ["roleId"] = u.RoleId, ["auditorId"] = u.AuditorId,
            ["active"] = u.Active, ["passwordHash"] = u.PasswordHash
        }).ToArray())
    };
    return Results.Text(o.ToJsonString(), "application/json");
});

app.MapPost("/api/restore", async (JsonObject s, HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me == null) return Results.Unauthorized();
    if (!Perm.IsFull(Perm.Roles(db), me)) return Err("الاستيراد لمدير النظام فقط", 403);
    var app0 = (string?)s["app"];
    var data = new Dictionary<string, JsonNode?>();
    List<AppUser>? newUsers = null;
    if (app0 == "nq-cert-server" && s["items"] is JsonObject its)
    {
        foreach (var kv in its) if (Perm.KeyMods.ContainsKey(kv.Key)) data[kv.Key] = kv.Value?["data"]?.DeepClone();
        if (s["users"] is JsonArray ua && ua.Count > 0)
            newUsers = ua.OfType<JsonObject>().Select(u => new AppUser
            {
                Username = ((string?)u["username"] ?? "").ToLowerInvariant(), Name = (string?)u["name"] ?? "",
                RoleId = Perm.Int(u["roleId"]) ?? 0, AuditorId = Perm.Int(u["auditorId"]),
                Active = u["active"]?.GetValue<bool>() ?? true, PasswordHash = (string?)u["passwordHash"] ?? ""
            }).Where(u => u.Username != "" && u.Username != Emergency.User && u.PasswordHash.StartsWith("pbkdf2$")).ToList();
    }
    else if (app0 == "nq-cert" && s["db"] is JsonObject odb)   // نسخة من النسخة الأولى (ملف HTML المستقل) — بيانات فقط
    {
        foreach (var kv in odb) if (Perm.KeyMods.ContainsKey(kv.Key)) data[kv.Key] = kv.Value?.DeepClone();
        if (s["lists"] != null) data["lists"] = s["lists"]!.DeepClone();
        if (s["usedNos"] != null) data["usedNos"] = s["usedNos"]!.DeepClone();
    }
    else return Err("الملف ليس نسخة احتياطية من هذا النظام");
    if (data.Count == 0) return Err("النسخة لا تحتوي بيانات");

    var roles = data.TryGetValue("roles", out var rn) && rn is JsonArray ra ? ra : Perm.Roles(db);
    if (!roles.OfType<JsonObject>().Any(x => Perm.IsFull(roles, Perm.Int(x["id"]) ?? -1))) return Err("النسخة لا تحتوي دور مدير نظام");
    if (newUsers != null && !newUsers.Any(u => u.Active && Perm.IsFull(roles, u.RoleId))) newUsers = null; // نحافظ على المستخدمين الحاليين

    var old = await db.Items.ToDictionaryAsync(i => i.Key);
    foreach (var (k, v) in data)
    {
        if (!old.TryGetValue(k, out var it)) { it = new DataItem { Key = k }; db.Items.Add(it); }
        it.Json = Perm.Clean(v)?.ToJsonString() ?? "null"; it.Version += 1; it.UpdatedBy = me.Username; it.UpdatedAt = DateTime.UtcNow;
    }
    if (newUsers != null)
    {
        db.Users.RemoveRange(db.Users);
        await db.SaveChangesAsync();
        db.Users.AddRange(newUsers);
    }
    db.Log(me.Username, "استيراد نسخة احتياطية" + (newUsers != null ? " (مع المستخدمين)" : ""), Ip(ctx));
    await db.SaveChangesAsync();
    return Results.Ok(new { ok = true, usersReplaced = newUsers != null });
});

// ---------------- emergency (erpadmin only) ----------------
app.MapPost("/api/emergency/{action}", async (string action, JsonObject? body, HttpContext ctx, AppDb db) =>
{
    var me = await GetMe(ctx, db);
    if (me == null) return Results.Unauthorized();
    if (!me.Power) return Err("لحساب الطوارئ فقط", 403);
    var ip = Ip(ctx);
    switch (action)
    {
        case "restore-admin":
        {
            var roles = Perm.Roles(db);
            var full = roles.OfType<JsonObject>().FirstOrDefault(x => Perm.IsFull(roles, Perm.Int(x["id"]) ?? -1));
            if (full == null)
            {
                var nid = roles.OfType<JsonObject>().Select(x => Perm.Int(x["id"]) ?? 0).DefaultIfEmpty(0).Max() + 1;
                full = new JsonObject { ["id"] = nid, ["name"] = "مدير النظام", ["all"] = true, ["locked"] = true, ["perms"] = new JsonObject() };
                roles.Insert(0, full);
                var it = await db.Items.FirstOrDefaultAsync(i => i.Key == "roles");
                if (it == null) { it = new DataItem { Key = "roles" }; db.Items.Add(it); }
                it.Json = roles.ToJsonString(); it.Version += 1; it.UpdatedBy = me.Username; it.UpdatedAt = DateTime.UtcNow;
            }
            var a = await db.Users.FirstOrDefaultAsync(x => x.Username == "admin");
            if (a == null) { a = new AppUser { Username = "admin", Name = "مدير النظام" }; db.Users.Add(a); }
            a.PasswordHash = Pw.Hash("admin"); a.Active = true; a.RoleId = Perm.Int(full["id"])!.Value; a.Fails = 0; a.LockUntil = null; a.Stamp = Guid.NewGuid().ToString("N");
            db.Log(me.Username, "طوارئ: استعادة حساب admin", ip);
            break;
        }
        case "unlock-all":
            foreach (var u in db.Users) { u.Fails = 0; u.LockUntil = null; }
            db.Log(me.Username, "طوارئ: فك قفل كل الحسابات", ip);
            break;
        case "reset":
            if ((string?)body?["confirm"] != "RESET") return Err("اكتب RESET للتأكيد");
            await db.Items.ExecuteDeleteAsync();
            await db.Users.ExecuteDeleteAsync();
            await db.Logs.ExecuteDeleteAsync();
            db.Log(me.Username, "طوارئ: إعادة ضبط المصنع", ip);
            await db.SaveChangesAsync();
            Seed.Run(db);
            return Results.Ok(new { ok = true });
        default: return Err("إجراء غير معروف", 404);
    }
    await db.SaveChangesAsync();
    return Results.Ok(new { ok = true });
});

// ---------------- QR + public certificate verification ----------------
app.MapGet("/qr", (string? d) =>
{
    d ??= ""; if (d.Length > 600) d = d[..600];
    using var gen = new QRCoder.QRCodeGenerator();
    using var data = gen.CreateQrCode(d, QRCoder.QRCodeGenerator.ECCLevel.M);
    var svg = new QRCoder.SvgQRCode(data).GetGraphic(new System.Drawing.Size(256, 256), "#000000", "#ffffff", true, QRCoder.SvgQRCode.SizingMode.ViewBoxAttribute);
    return Results.Text(svg, "image/svg+xml");
}).RequireRateLimiting("public");

app.MapGet("/verify", async (string? no, AppDb db) =>
{
    if (!dbcfg.Configured) return Results.Text("Not configured", "text/plain");
    static string H(string? s) => System.Net.WebUtility.HtmlEncode(s ?? "");
    static string F(string? d) => string.IsNullOrEmpty(d) ? "—" : string.Join("-", d.Split('-').Reverse());
    JsonArray Arr(string key) { var it = db.Items.AsNoTracking().FirstOrDefault(i => i.Key == key); try { return it == null ? new JsonArray() : JsonNode.Parse(it.Json) as JsonArray ?? new JsonArray(); } catch { return new JsonArray(); } }
    no = (no ?? "").Trim();
    JsonObject? c = no == "" ? null : Arr("certificates").OfType<JsonObject>().FirstOrDefault(x => string.Equals((string?)x["no"], no, StringComparison.OrdinalIgnoreCase));
    string body;
    if (c == null)
        body = $"<div class='st bad'>✕</div><h1>الشهادة غير موجودة<br><small>Certificate not found</small></h1><p class='no'>{H(no)}</p><p class='mu'>تأكد من رقم الشهادة أو تواصل مع الجهة المانحة.<br>Please check the number or contact the issuing body.</p>";
    else
    {
        var comp = Arr("companies").OfType<JsonObject>().FirstOrDefault(x => Perm.Int(x["id"]) == Perm.Int(c["comp"]));
        var std = Arr("standards").OfType<JsonObject>().FirstOrDefault(x => Perm.Int(x["id"]) == Perm.Int(c["std"]));
        var status = (string?)c["status"] ?? "";
        var exp = (string?)c["extDate"]; if (string.IsNullOrEmpty(exp)) exp = (string?)c["exp"];
        bool valid = status == "ساري" && (string.IsNullOrEmpty(exp) || string.CompareOrdinal(exp, DateTime.UtcNow.ToString("yyyy-MM-dd")) >= 0);
        var en = status switch { "ساري" => "Valid", "منتهي" => "Expired", "ملغي" => "Withdrawn", "موقوف" => "Suspended", "قيد الإصدار" => "Being issued", _ => status };
        if (status == "ساري" && !valid) { status = "منتهي"; en = "Expired"; }
        var cname = (string?)comp?["nameEn"]; if (string.IsNullOrEmpty(cname)) cname = (string?)comp?["name"];
        body = $@"<div class='st {(valid ? "ok" : "bad")}'>{(valid ? "✓" : "!")}</div>
<h1>{(valid ? "شهادة سارية" : "الشهادة غير سارية")}<br><small>{(valid ? "Valid certificate" : "Certificate is not valid")} — {H(en)}</small></h1>
<table><tr><th>رقم الشهادة<br><small>Certificate No.</small></th><td dir='ltr'>{H((string?)c["no"])}</td></tr>
<tr><th>الجهة<br><small>Organization</small></th><td>{H(cname)}</td></tr>
<tr><th>المعيار<br><small>Standard</small></th><td dir='ltr'>{H((string?)std?["code"])}</td></tr>
<tr><th>الحالة<br><small>Status</small></th><td>{H(status)} / {H(en)}</td></tr>
<tr><th>تاريخ الإصدار<br><small>Issue date</small></th><td dir='ltr'>{F((string?)c["issue"])}</td></tr>
<tr><th>تاريخ الانتهاء<br><small>Expiry date</small></th><td dir='ltr'>{F(exp)}</td></tr></table>";
    }
    var html = $@"<!DOCTYPE html><html lang='ar' dir='rtl'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>التحقق من الشهادة — Certificate verification</title>
<style>body{{margin:0;font-family:Segoe UI,Tahoma,sans-serif;background:#f4f6fc;color:#0f1250;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px;box-sizing:border-box}}
.c{{background:#fff;border-radius:28px;box-shadow:0 20px 50px rgba(15,18,80,.1);padding:32px 28px;max-width:520px;width:100%;text-align:center}}
.st{{width:72px;height:72px;border-radius:50%;margin:0 auto 14px;display:grid;place-items:center;font-size:36px;color:#fff;font-weight:700}}.ok{{background:#00a37a}}.bad{{background:#e0384b}}
h1{{font-size:22px;margin:0 0 18px}}h1 small{{font-size:14px;color:#5f6589;font-weight:500}}table{{width:100%;border-collapse:collapse;text-align:start}}
th,td{{padding:11px 8px;border-bottom:1px solid #e6e9f5;font-size:14px;vertical-align:top}}th{{color:#5f6589;font-weight:600;width:42%}}th small{{font-weight:400}}
.no{{font-size:18px;font-weight:700;direction:ltr}}.mu{{color:#5f6589;font-size:14px;line-height:1.7}}.f{{margin-top:18px;color:#5f6589;font-size:12px}}</style></head>
<body><div class='c'>{body}<div class='f'>National Quality — Certificate verification</div></div></body></html>";
    return Results.Content(html, "text/html; charset=utf-8");
}).RequireRateLimiting("public");

app.MapFallback(async ctx =>
{
    if (ctx.Request.Path.StartsWithSegments("/api")) { ctx.Response.StatusCode = 404; return; }
    ctx.Response.ContentType = "text/html; charset=utf-8";
    await ctx.Response.SendFileAsync(Path.Combine(app.Environment.WebRootPath, "index.html"));
});

app.Run();

record LoginReq(string? Username, string? Password);
record PwReq(string? Current, string? New);
record SetupReq(string? EmergencyPassword, string? Provider, string? ConnectionString);
record UserReq(int? Id, string? Username, string? Name, int RoleId, int? AuditorId, bool Active, string? Password);
record Change(string? Key, JsonNode? Data, int BaseVersion);
record SaveReq(List<Change>? Changes);
