using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace PdfSignApp
{
  // Define the input objects for presign and sign commands
  public class PreSignInput
  {
    public string CertificatePem { get; set; } = "";
    public string PdfContent { get; set; } = "";
    public string Location { get; set; } = "";
    public string Reason { get; set; } = "";
    public SignRect SignRect { get; set; } = new SignRect();
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

    internal DigestCalcBlankSigner(PdfName filter, PdfName subFilter)
    {
      _docBytesHash = Array.Empty<byte>();
      _filter = filter;
      _subFilter = subFilter;
    }

    internal virtual byte[] GetDocBytesHash()
    {
      return _docBytesHash;
    }

    public virtual byte[] Sign(Stream docBytes)
    {
      _docBytesHash = CalcDocBytesHash(docBytes);
      // Return empty signature bytes as placeholder
      return Array.Empty<byte>();
    }

    public virtual void ModifySigningDictionary(PdfDictionary signDic)
    {
      signDic.Put(PdfName.Filter, _filter);
      signDic.Put(PdfName.SubFilter, _subFilter);
    }

    internal static byte[] CalcDocBytesHash(Stream docBytes)
    {
      return DigestAlgorithms.Digest(docBytes, DigestUtilities.GetDigest(DigestAlgorithms.SHA256));
    }
  }

  class Program
  {
    static void Main(string[] args)
    {
      if (args.Length < 1)
      {
        PrintUsage();
        return;
      }

      string command = args[0].ToLowerInvariant();

      try
      {
        switch (command)
        {
          case "presign":
            // Usage: PdfSignApp presign <base64_presign_input>
            if (args.Length < 2)
            {
              Console.Error.WriteLine("Missing base64-encoded presign input.");
              return;
            }
            HandlePreSign(args[1]);
            break;

          case "sign":
            // Usage: PdfSignApp sign <base64_sign_input>
            if (args.Length < 2)
            {
              Console.Error.WriteLine("Missing base64-encoded sign input.");
              return;
            }
            HandleSign(args[1]);
            break;

          default:
            PrintUsage();
            break;
        }
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine("An unexpected error occurred: " + ex.Message);
      }
    }

    /// <summary>
    /// Handles the presign command.
    /// </summary>
    /// <param name="base64Input">Base64-encoded PreSignInput JSON string.</param>
    static void HandlePreSign(string base64Input)
    {
      PreSignInput input;
      try
      {
        string json = Encoding.UTF8.GetString(Convert.FromBase64String(base64Input));
        input = JsonSerializer.Deserialize<PreSignInput>(json);
        if (input == null)
        {
          throw new Exception("Deserialized input is null.");
        }
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine("Error decoding and parsing presign input: " + ex.Message);
        return;
      }

      byte[] originalPdf;
      try
      {
        originalPdf = Convert.FromBase64String(input.PdfContent);
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine("Error decoding base64 PDF content: " + ex.Message);
        return;
      }

      // Create the signer container
      DigestCalcBlankSigner preSignContainer = new DigestCalcBlankSigner(PdfName.Adobe_PPKLite, PdfName.Adbe_pkcs7_detached);

      byte[] pdfWithPlaceholder;
      try
      {
        pdfWithPlaceholder = CreatePreSignedPdf(originalPdf, preSignContainer, input);
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine("Error creating presigned PDF: " + ex.Message);
        return;
      }

      // Write the presigned PDF to a temp file
      string preSignedPdfPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "presigned_" + Guid.NewGuid().ToString("N") + ".pdf");
      File.WriteAllBytes(preSignedPdfPath, pdfWithPlaceholder);

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
    }

    /// <summary>
    /// Handles the sign command.
    /// </summary>
    /// <param name="base64Input">Base64-encoded SignInput JSON string.</param>
    static void HandleSign(string base64Input)
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
        return;
      }

      if (!File.Exists(input.PresignedPdfPath))
      {
        Console.Error.WriteLine("Pre-signed PDF not found: " + input.PresignedPdfPath);
        return;
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
        return;
      }

      // Output the final PDF to a temp file
      string finalPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "signed_" + Guid.NewGuid().ToString("N") + ".pdf");
      File.WriteAllBytes(finalPath, fullySignedPdf);

      // Prepare the output object
      var output = new
      {
        SignedPdfPath = finalPath
      };

      string outputJson = JsonSerializer.Serialize(output);
      string outputBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(outputJson));

      // Output the base64-encoded JSON
      Console.WriteLine(outputBase64);
    }

    /// <summary>
    /// Creates a pre-signed PDF with a placeholder signature.
    /// </summary>
    static byte[] CreatePreSignedPdf(byte[] originalPdf, DigestCalcBlankSigner container, PreSignInput input)
    {
      using var msIn = new MemoryStream(originalPdf);
      using var msOut = new MemoryStream();

      X509Certificate[] chain = { Utils.LoadCertificateFromPem(input.CertificatePem) };
      var reader = new PdfReader(msIn);
      var signer = new CustomPdfSigner(reader, msOut, new StampingProperties().UseAppendMode());

      // Setup signature appearance
      var appearance = signer.GetSignatureAppearance()
                               .SetReason(input.Reason)
                               .SetLocation(input.Location)
                               .SetPageRect(new Rectangle(input.SignRect.X, input.SignRect.Y, input.SignRect.Width, input.SignRect.Height))
                               .SetPageNumber(1)
                               .SetCertificate(chain[0]);

      signer.SignExternalContainer(container, 8192);

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
      var signer = new PdfSigner(reader, msOut, new StampingProperties().UseAppendMode());

      // Load certificate (optional, based on your requirements)
      // If needed, you can extract the certificate from the pre-signed PDF or pass it via input
      // For this example, we'll assume it's not needed in this step

      X509Certificate[] chain = { Utils.LoadCertificateFromPem(signInput.CertificatePem) };

      // Create the PKCS7 signature
      PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", false);
      byte[] hash = DigestAlgorithms.Digest(msIn, DigestUtilities.GetDigest("SHA256"));

      byte[] authenticatedAttributes = sgn.GetAuthenticatedAttributeBytes(hash, PdfSigner.CryptoStandard.CMS, null, null);
      byte[] signatureBytes = HexStringToByteArray(signInput.SignedHash);

      sgn.SetExternalDigest(signatureBytes, null, "RSA");
      byte[] pkcs7 = sgn.GetEncodedPKCS7(hash, PdfSigner.CryptoStandard.CMS, null, null, null);

      // Inject the final signature
      var container = new FinalSignatureContainer(pkcs7);
      PdfSigner.SignDeferred(signer.GetDocument(), "Signature1", msOut, container);

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

  /// <summary>
  /// A custom signature container for the final step. This container simply
  /// returns the final signature bytes (CMS/PKCS#7) that the client computed.
  /// </summary>
  public class FinalSignatureContainer : IExternalSignatureContainer
  {
    private readonly byte[] _signature;

    public FinalSignatureContainer(byte[] signature)
    {
      _signature = signature;
    }

    public void ModifySigningDictionary(PdfDictionary signDic)
    {
      // Optionally modify the signing dictionary if needed
      // For example, you can set the SubFilter here if not already set
      // signDic.Put(PdfName.SubFilter, PdfName.Adbe_pkcs7_detached);
    }

    public byte[] Sign(Stream data)
    {
      // Return the final signature bytes provided by the client
      return _signature;
    }
  }
}
