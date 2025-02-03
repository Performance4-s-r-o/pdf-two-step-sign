using System;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using iText.IO.Image;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Layout.Element;
using iText.Signatures;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DotNetRuntime
{
  // Define the input objects for presign and sign commands
  public class PreSignInput
  {
    public string CertificatePem { get; set; } = "";
    public string PdfContent { get; set; } = "";
    public string Location { get; set; } = "";
    public string Reason { get; set; } = "";
    public SignRect SignRect { get; set; } = new SignRect();
    public string? SignImageContent { get; set; } = "";
    public string? SignImageBackgroundContent { get; set; } = "";
    public int SignPageNumber { get; set; } = 1;
  }

  public class SignRect
  {
    public float X { get; set; }
    public float Y { get; set; }
    public float Width { get; set; }
    public float Height { get; set; }
  }

  public class SignInput
  {
    public string CertificatePem { get; set; } = "";
    public string SignedHash { get; set; } = "";
    public string PresignedPdfPath { get; set; } = "";
    public string HashToSign { get; set; } = "";
  }

  class CustomPdfSigner : PdfSigner
  {
    public CustomPdfSigner(PdfReader reader, Stream outputStream, StampingProperties properties) : base(reader, outputStream, properties) { }

    public Stream CustomGetRangeStream()
    {
      return GetRangeStream();
    }
  }

  internal class DigestCalcBlankSigner : IExternalSignatureContainer
  {
    private readonly PdfName _filter;
    private readonly PdfName _subFilter;
    private byte[] _docBytesHash;

    private X509Certificate[] _chain;

    internal DigestCalcBlankSigner(PdfName filter, PdfName subFilter)
    {
      _docBytesHash = Array.Empty<byte>();
      _filter = filter;
      _subFilter = subFilter;
    }

    public virtual void SetChain(X509Certificate[] chain)
    {
      _chain = chain;
    }

    internal virtual byte[] GetDocBytesHash()
    {
      return _docBytesHash;
    }

    public virtual byte[] Sign(Stream docBytes)
    {
      _docBytesHash = CalcDocBytesHash(docBytes, _chain);
      // Return empty signature bytes as placeholder
      return Array.Empty<byte>();
    }

    public virtual void ModifySigningDictionary(PdfDictionary signDic)
    {
      signDic.Put(PdfName.Filter, _filter);
      signDic.Put(PdfName.SubFilter, _subFilter);
      signDic.Put(PdfName.Contents, new PdfNumber(16386));
    }

    internal static byte[] CalcDocBytesHash(Stream docBytes, X509Certificate[] chain)
    {


      var digest = DigestAlgorithms.Digest(docBytes, DigestUtilities.GetDigest(DigestAlgorithms.SHA256));
      PdfPKCS7 signature = new PdfPKCS7(null, chain, "SHA256", false);
      return signature.GetAuthenticatedAttributeBytes(digest, PdfSigner.CryptoStandard.CMS, null, null);
    }
  }

  class PdfSignProgram
  {
    /// <summary>
    /// Handles the presign command.
    /// </summary>
    /// <param name="base64Input">Base64-encoded PreSignInput JSON string.</param>
    public static string? HandlePreSign(string base64Input, RuntimeContext Context)
    {
      PreSignInput input;
      try
      {
        string json = Encoding.UTF8.GetString(Convert.FromBase64String(base64Input));
        Context.Log(new { json });
        input = JsonSerializer.Deserialize<PreSignInput>(json);
        if (input == null)
        {
          throw new Exception("Deserialized input is null.");
        }
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine("Error decoding and parsing presign input: " + ex.Message);
        return null;
      }

      byte[] originalPdf;
      try
      {
        originalPdf = Convert.FromBase64String(input.PdfContent);
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine("Error decoding base64 PDF content: " + ex.Message);
        return null;
      }

      // Create the signer container
      DigestCalcBlankSigner preSignContainer = new DigestCalcBlankSigner(PdfName.Adobe_PPKLite, PdfName.Adbe_pkcs7_detached);

      byte[] pdfWithPlaceholder;
      try
      {
        pdfWithPlaceholder = CreatePreSignedPdf(originalPdf, preSignContainer, input, Context);
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine("Error creating presigned PDF: " + ex.Message);
        return null;
      }

      // Write the presigned PDF to a temp file
      string preSignedPdfPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "presigned_" + Guid.NewGuid().ToString("N") + ".pdf");
      File.WriteAllBytes(preSignedPdfPath, pdfWithPlaceholder);
      File.WriteAllBytes(preSignedPdfPath + ".original.pdf", originalPdf);

      // Prepare the output object
      var output = new
      {
        PresignedPdfPath = preSignedPdfPath,
        HashToSign = BitConverter.ToString(preSignContainer.GetDocBytesHash()).Replace("-", "").ToLowerInvariant()
      };

      string outputJson = JsonSerializer.Serialize(output);
      string outputBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputJson));

      // Output the base64-encoded JSON
      Console.WriteLine(outputBase64);
      return outputBase64;
    }

    /// <summary>
    /// Handles the sign command.
    /// </summary>
    /// <param name="base64Input">Base64-encoded SignInput JSON string.</param>
    public static string? HandleSign(string base64Input)
    {
      SignInput input;
      try
      {
        string json = Encoding.UTF8.GetString(Convert.FromBase64String(base64Input));
        input = JsonSerializer.Deserialize<SignInput>(json);
        if (input == null)
        {
          throw new Exception("Deserialized input is null.");
        }
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine("Error decoding and parsing sign input: " + ex.Message);
        return null;
      }

      if (!File.Exists(input.PresignedPdfPath))
      {
        Console.Error.WriteLine("Pre-signed PDF not found: " + input.PresignedPdfPath);
        return null;
      }

      byte[] preSignedPdf = File.ReadAllBytes(input.PresignedPdfPath);
      byte[] fullySignedPdf;
      try
      {
        fullySignedPdf = InjectFinalSignature(preSignedPdf, input);
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine("Error finalizing PDF signature: " + ex);
        return null;
      }

      return ConvertToBase64(fullySignedPdf);
    }

    /// <summary>
    /// Creates a pre-signed PDF with a placeholder signature.
    /// </summary>
    static byte[] CreatePreSignedPdf(byte[] originalPdf, DigestCalcBlankSigner container, PreSignInput input, RuntimeContext context)
    {
      using var msIn = new MemoryStream(originalPdf);
      using var msOut = new MemoryStream();

      X509Certificate[] chain = { Utils.LoadCertificateFromPem(input.CertificatePem) };
      container.SetChain(chain);
      var reader = new PdfReader(msIn);
      var signer = new CustomPdfSigner(reader, msOut, new StampingProperties().UseAppendMode());

      // Setup signature appearance
      var appearance = signer.GetSignatureAppearance();

      appearance.SetReason(input.Reason)
      .SetLocation(input.Location)
      .SetPageRect(new Rectangle(input.SignRect.X, input.SignRect.Y, input.SignRect.Width, input.SignRect.Height))
      .SetPageNumber(input.SignPageNumber);

      if (!String.IsNullOrEmpty(input.SignImageContent))
      {
        byte[] image = Convert.FromBase64String(input.SignImageContent);
        appearance.SetSignatureGraphic(ImageDataFactory.Create(image));
        appearance.SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION);
      }

      appearance.SetCertificate(chain[0]);

      signer.SetCertificationLevel(PdfSigner.NOT_CERTIFIED);
      signer.SignExternalContainer(container, 16386);

      return msOut.ToArray();
    }

    /// <summary>
    /// Injects the final signature into the pre-signed PDF.
    /// </summary>
    static byte[] InjectFinalSignature(byte[] pdfWithPlaceholder, SignInput signInput)
    {
      using var msIn = new MemoryStream(pdfWithPlaceholder);
      using var msOut = new MemoryStream();

      var reader = new PdfReader(msIn);
      var signer = new PdfSigner(reader, msOut, new StampingProperties());

      X509Certificate[] chain = { Utils.LoadCertificateFromPem(signInput.CertificatePem) };
      byte[] signatureBytes = HexStringToByteArray(signInput.SignedHash);
      IExternalSignatureContainer external = new MyExternalSignatureContainer(chain, signatureBytes);
      // Signs a PDF where space was already reserved. The field must cover the whole document.
      PdfSigner.SignDeferred(signer.GetDocument(), "Signature1", msOut, external);
      return msOut.ToArray();
    }

    /// <summary>
    /// Converts a hex string to a byte array.
    /// </summary>
    private static byte[] HexStringToByteArray(string hex)
    {
      if (hex.Length % 2 != 0)
        throw new ArgumentException("Hex string must have an even length.");

      byte[] bytes = new byte[hex.Length / 2];

      for (int i = 0; i < hex.Length; i += 2)
      {
        string part = hex.Substring(i, 2);
        bytes[i / 2] = Convert.ToByte(part, 16);
      }

      return bytes;
    }

    static string ConvertToBase64(byte[] data)
    {
      if (data == null)
      {
        throw new ArgumentNullException(nameof(data), "Input byte array cannot be null.");
      }

      return Convert.ToBase64String(data);
    }

    static void PrintUsage()
    {
      Console.WriteLine("Usage:");
      Console.WriteLine("  PdfSignApp presign <base64_presign_input>");
      Console.WriteLine("     -> base64_presign_input is a base64-encoded JSON object:");
      Console.WriteLine("        {");
      Console.WriteLine("          \"CertificatePem\": \"<PEM_CERTIFICATE>\",");
      Console.WriteLine("          \"PdfContent\": \"<base64_pdf_content>\",");
      Console.WriteLine("          \"Location\": \"<Location>\",");
      Console.WriteLine("          \"Reason\": \"<Reason>\",");
      Console.WriteLine("          \"SignRect\": { \"X\": <float>, \"Y\": <float>, \"Width\": <float>, \"Height\": <float> }");
      Console.WriteLine("        }");
      Console.WriteLine();
      Console.WriteLine("  PdfSignApp sign <base64_sign_input>");
      Console.WriteLine("     -> base64_sign_input is a base64-encoded JSON object:");
      Console.WriteLine("        {");
      Console.WriteLine("          \"PresignedPdfPath\": \"<path_to_presigned_pdf>\",");
      Console.WriteLine("          \"SignedHash\": \"<hex_signed_hash>\"");
      Console.WriteLine("        }");
      Console.WriteLine();
    }
  }

  /// <summary>
  /// A utility class for loading certificates and other helper methods.
  /// </summary>
  public static class Utils
  {
    /// <summary>
    /// Loads an X509 certificate from a PEM string.
    /// </summary>
    public static Org.BouncyCastle.X509.X509Certificate LoadCertificateFromPem(string pem)
    {
      var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(new StringReader(pem));
      var certObject = pemReader.ReadObject();
      if (certObject is Org.BouncyCastle.X509.X509Certificate certificate)
      {
        return certificate;
      }
      throw new ArgumentException("Invalid PEM certificate.");
    }
  }

  class MyExternalSignatureContainer : IExternalSignatureContainer
  {

    protected X509Certificate[] chain;
    protected Stream localInputStream;
    protected byte[] signature;

    public MyExternalSignatureContainer(X509Certificate[] chain, byte[] signature)
    {
      this.signature = signature;
      this.chain = chain;
    }

    public byte[] Sign(Stream inputStream)
    {
      try
      {
        PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", false);
        byte[] hash = DigestAlgorithms.Digest(inputStream, DigestUtilities.GetDigest("SHA256"));
        sgn.SetExternalDigest(signature, null, "RSA");

        return sgn.GetEncodedPKCS7(hash, PdfSigner.CryptoStandard.CMS, null,
            null, null);
      }
      catch (IOException ioe)
      {
        throw new Exception(ioe.Message);
      }
    }

    public void ModifySigningDictionary(PdfDictionary signDic)
    {
    }
  }
}

