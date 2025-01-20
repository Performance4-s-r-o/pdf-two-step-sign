namespace DotNetRuntime;

using PdfSignApp;
// using LocalDotNetRuntime;
using System.Text.Json;

public class Handler
{
  // This Appwrite function will be executed every time your function is triggered
  public async Task<RuntimeOutput> Main(RuntimeContext Context)
  {
    Context.Req.BodyJson.TryGetValue("content", out object? contentObject);
    Context.Req.BodyJson.TryGetValue("type", out object? typeObject);

    string? content = ((JsonElement)contentObject).GetString();
    string? type = ((JsonElement)typeObject).GetString();

    if (content == null || type == null)
    {
      return Context.Res.Json(new Dictionary<string, object?>()
      {
        { "error", "Missing content or type" }
      });
    }

    if (type == "presign" && content != "")
    {
      var response = PdfSignProgram.HandlePreSign(content.ToString());
      return Context.Res.Json(new Dictionary<string, object?>()
      {
        { "content", response }
      });
    }

    if (type == "sign" && content != "")
    {
      var response = PdfSignProgram.HandleSign(content);

      return Context.Res.Json(new Dictionary<string, object?>()
      {
        { "content", response }
      });
    }

    return Context.Res.Json(new Dictionary<string, object?> { });
  }
}


