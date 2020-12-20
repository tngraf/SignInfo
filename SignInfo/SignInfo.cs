// ---------------------------------------------------------------------------
// <copyright file="SignInfo.cs" company="Tethys">
//   Copyright (C) 2020 T. Graf
// </copyright>
//
// Licensed under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied.
// ---------------------------------------------------------------------------

namespace SignInfo
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Reflection;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;

    /// <summary>
    /// Core class.
    /// </summary>
    public class SignInfo
    {
        #region PRIVATE PROPERTIES
        /// <summary>
        /// The backup color.
        /// </summary>
        private readonly ConsoleColor backupColor;
        #endregion // PRIVATE PROPERTIES

        //// ---------------------------------------------------------------------

        #region PUBLIC PROPERTIES
        /// <summary>
        /// Gets or sets a value indicating whether to show file hashes.
        /// </summary>
        public bool ShowFileHashes { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to show the signing chain.
        /// </summary>
        public bool ShowSigningChain { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to show extended version information.
        /// </summary>
        public bool ShowExtendedVersionInfo { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to show the online help.
        /// </summary>
        public bool ShowHelp { get; set; }

        /// <summary>
        /// Gets or sets the file spec.
        /// </summary>
        public string FileSpec { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to suppress the banner.
        /// </summary>
        public bool NoBanner { get; set; }
        #endregion // PUBLIC PROPERTIES

        //// ---------------------------------------------------------------------

        #region CONSTRUCTION
        /// <summary>
        /// Initializes a new instance of the <see cref="SignInfo"/> class.
        /// </summary>
        public SignInfo()
        {
            this.backupColor = Console.ForegroundColor;
            this.ShowFileHashes = false;
            this.ShowSigningChain = false;
            this.ShowExtendedVersionInfo = false;
            this.ShowHelp = false;
        } // SignInfo()
        #endregion // CONSTRUCTION

        //// ---------------------------------------------------------------------

        #region PUBLIC METHODS
        /// <summary>
        /// Runs the specified arguments.
        /// </summary>
        /// <param name="args">The arguments.</param>
        /// <returns>A <see cref="ReturnCode"/> value.</returns>
        public int Run(string[] args)
        {
            if (!this.ParseCommandLine(args))
            {
                DisplayBanner();
                DisplayHelp();
                return (int)ReturnCode.InsufficientArguments;
            } // if

            if (!this.NoBanner)
            {
                DisplayBanner();
            } // if

            if (this.ShowHelp)
            {
                DisplayHelp();
                return (int)ReturnCode.InsufficientArguments;
            } // if

            return this.AnalyzeFile(this.FileSpec);
        } // Run()

        /// <summary>
        /// Analyzes the given file.
        /// </summary>
        /// <param name="filename">The filename.</param>
        /// <returns>A <see cref="ReturnCode"/> value.</returns>
        public int AnalyzeFile(string filename)
        {
            var fi = new FileInfo(filename);
            if (!fi.Exists)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("File does not exist!");
                Console.ForegroundColor = this.backupColor;
                return (int)ReturnCode.FileNotFound;
            } // if

            Console.WriteLine(fi.FullName);
            ReturnCode returnValue;

            try
            {
                var cert = X509Certificate.CreateFromSignedFile(filename);
                var cert2 = new X509Certificate2(cert);
                var validChain = BuildCertificateChain(cert2, out var signInfo);
                returnValue = (validChain == "Signed")
                    ? ReturnCode.FileSignedAndVerified : ReturnCode.FileSignatureNotVerified;

                Console.WriteLine("  Verified:        " + validChain);
                Console.WriteLine("  Publisher:       " + GetFriendlyCertificateName(cert2));
                this.ShowFileProperties(fi.FullName);

                if (this.ShowSigningChain)
                {
                    Console.Write(signInfo);
                } // if

                cert2.Dispose();
                cert.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  Verified:        Unsigned ({ex.Message})");
                returnValue = ReturnCode.FileNotSigned;
                Console.WriteLine("  Publisher:       n/a");
                this.ShowFileProperties(fi.FullName);
            } // catch

            if (this.ShowFileHashes)
            {
                PrintFileHashes(fi.FullName);
            } // if

            return (int)returnValue;
        } // AnalyzeFile()
        #endregion // PUBLIC METHODS

        //// ---------------------------------------------------------------------

        #region PRIVATE METHODS
        /// <summary>
        /// Shows the file properties.
        /// </summary>
        /// <param name="filename">The filename.</param>
        private void ShowFileProperties(string filename)
        {
            var versionInfo = FileVersionInfo.GetVersionInfo(filename);

            // Link Date
            // Publisher
            Console.WriteLine("  Company:         " + versionInfo.CompanyName);
            Console.WriteLine("  Description:     " + versionInfo.FileDescription);
            Console.WriteLine("  Product:         " + versionInfo.ProductName);
            Console.WriteLine("  Product Version: " + versionInfo.ProductVersion);
            Console.WriteLine("  File Version:    " + versionInfo.FileVersion);
            if (this.ShowExtendedVersionInfo)
            {
                Console.WriteLine(
                    "  Binary Version:  {0}.{1}.{2}.{3}",
                    versionInfo.FileMajorPart,
                    versionInfo.FileMinorPart,
                    versionInfo.FileBuildPart,
                    versionInfo.FilePrivatePart);
                Console.WriteLine("  Original Name:   " + versionInfo.OriginalFilename);
                Console.WriteLine("  Internal Name:   " + versionInfo.InternalName);

                Console.WriteLine("  Copyright:       " + versionInfo.LegalCopyright);
                Console.WriteLine("  Comments:        " + versionInfo.Comments);
                // Comments
            } // if
        } // ShowFileProperties()

        /// <summary>
        /// Builds the certificate chain.
        /// </summary>
        /// <param name="cert">The cert.</param>
        /// <param name="chainInfo">The chain information.</param>
        /// <returns>
        /// A textual description of the chain status.
        /// </returns>
        private static string BuildCertificateChain(X509Certificate2 cert, out string chainInfo)
        {
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            var built = chain.Build(cert);

            chainInfo = string.Empty;

            if (chain.ChainStatus.Length > 0)
            {
                var list = new List<string>();
                foreach (var status in chain.ChainStatus)
                {
#if false // detailed output
                    Console.WriteLine("Chain Status: " + status.Status);
                    Console.WriteLine("Chain Status Information: " + status.StatusInformation);
#endif
                    list.Add(status.StatusInformation);
                } // foreach

                return string.Join(", ", list);
            } // if

            if (built)
            {
                // chain is valid
                var sb = new StringBuilder(1000);
                sb.Append("  Signers:\n");
                foreach (var element in chain.ChainElements)
                {
                    sb.Append($"    {GetFriendlyCertificateName(element.Certificate)}\n");
                    var status = element.Certificate.Verify() ? "Valid" : "NOT VALID!";
                    sb.Append($"      Cert Status: {status}\n");
                    sb.Append($"      Issuer: {element.Certificate.GetNameInfo(X509NameType.SimpleName, true)}\n");
                    sb.Append($"      Algorithm: {element.Certificate.SignatureAlgorithm.FriendlyName}\n");
                    sb.Append($"      Serial Number: {element.Certificate.SerialNumber}\n");
                    sb.Append($"      Thumbprint: {element.Certificate.Thumbprint}\n");
                    sb.Append($"      Valid from: {element.Certificate.NotBefore}\n");
                    sb.Append($"      Valid until: {element.Certificate.NotAfter}\n");
                    sb.Append($"      Element error status length: {element.ChainElementStatus.Length}\n");
                    sb.Append($"      Valid Usage: {GetUsageString(element.Certificate)}\n");
                    sb.Append($"      Element information: {element.Information}\n");
                    sb.Append($"      Number of element extensions: {element.Certificate.Extensions.Count}\n");

                    if (chain.ChainStatus.Length > 1)
                    {
                        for (var index = 0; index < element.ChainElementStatus.Length; index++)
                        {
                            sb.Append(element.ChainElementStatus[index].Status + "\n");
                            sb.Append(element.ChainElementStatus[index].StatusInformation + "\n");
                        } // for
                    } // if

                    sb.Append("\n");
                } // foreach

                chainInfo = sb.ToString();
            }
            else
            {
                chainInfo = "Building certificate chain failed!";
                return "Unsigned";
            } // if

            return "Signed";
        } // BuildCertificateChain()

        /// <summary>
        /// Gets the friendly name of the certificate.
        /// </summary>
        /// <param name="cert">The cert.</param>
        /// <returns>A string with the friendly name.</returns>
        private static string GetFriendlyCertificateName(X509Certificate2 cert)
        {
            var data = cert.SubjectName.Decode(X500DistinguishedNameFlags.UseNewLines);
            if (string.IsNullOrEmpty(data))
            {
                return "???";
            } // if

            var lines = data.Split(new[] { '\n' });
            foreach (var line in lines)
            {
                // something like "CN=Json.NET (.NET Foundation)"
                if (line.StartsWith("CN="))
                {
                    return line.Substring(3);
                } // if
            } // foreach

            return "???";
        } // GetFriendlyCertificateName()

        /// <summary>
        /// Gets the usage string.
        /// </summary>
        /// <param name="cert">The cert.</param>
        /// <returns>The certificate usage text.</returns>
        private static string GetUsageString(X509Certificate2 cert)
        {
            var usageText = "Unknown";

            foreach (var certExtension in cert.Extensions)
            {
                // Console.WriteLine("FriendlyName: " + certExtension.Oid.FriendlyName);
                if (certExtension is X509KeyUsageExtension usage)
                {
                    usageText = usage.KeyUsages.ToString();
                } // if
            } // foreach

            return usageText;
        } // GetUsageString()

        /// <summary>
        /// Prints the file hashes.
        /// </summary>
        /// <param name="filename">The filename.</param>
        private static void PrintFileHashes(string filename)
        {
            try
            {
                using var stream = File.Open(filename, FileMode.Open, FileAccess.Read);
                var hash = CalculateMD5Hash(stream);
                Console.WriteLine($"  MD5 hash = {hash}");

                stream.Position = 0;
                hash = CalculateSha1Hash(stream);
                Console.WriteLine($"  SHA1 hash = {hash}");

                stream.Position = 0;
                hash = CalculateSha256Hash(stream);
                Console.WriteLine($"  SHA256 hash = {hash}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error calculating file hashes: " + ex.Message);
            } // catch
        } // PrintFileHashes()

        /// <summary>
        /// Calculates the MD5 hash.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>The MS5 hash as hex string.</returns>
        private static string CalculateMD5Hash(Stream input)
        {
            var md5 = MD5.Create();
            var hash = md5.ComputeHash(input);
            return GetHexString(hash);
        } // CalculateMD5Hash()

        /// <summary>
        /// Calculates the SHA1 hash.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>The SHA1 hash as hex string.</returns>
        private static string CalculateSha1Hash(Stream input)
        {
            var sha = SHA1.Create();
            var hash = sha.ComputeHash(input);
            return GetHexString(hash);
        } // CalculateSha1Hash()

        /// <summary>
        /// Calculates the SHA256 hash.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>The SHA256 hash as hex string.</returns>
        private static string CalculateSha256Hash(Stream input)
        {
            var sha = SHA256.Create();
            var hash = sha.ComputeHash(input);
            return GetHexString(hash);
        } // CalculateSha256Hash()

        /// <summary>
        /// Gets the hexadecimal string.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>The data as hex string.</returns>
        private static string GetHexString(IEnumerable<byte> data)
        {
            var sb = new StringBuilder();
            foreach (var b in data)
            {
                sb.Append(b.ToString("X2"));
            } // foreach

            return sb.ToString();
        } // GetHexString()

        /// <summary>
        /// Displays the banner.
        /// </summary>
        private static void DisplayBanner()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var version = assembly.GetName().Version;
            if (version == null)
            {
                return;
            } // if

            Console.WriteLine(
                "\r\nSignInfo {0}.{1}.{2} - Signature Information viewer.",
                version.Major,
                version.Minor,
                version.Revision);

            var copyright = string.Empty;
            var attribs = assembly.GetCustomAttributes(typeof(AssemblyCopyrightAttribute), true);
            if (attribs.Length > 0)
            {
                copyright = (attribs[0] as AssemblyCopyrightAttribute)?.Copyright;
            } // if

            if (!string.IsNullOrEmpty(copyright))
            {
                Console.WriteLine(copyright);
            } // if

            Console.WriteLine();
        } // DisplayBanner()

        /// <summary>
        /// Displays the help information.
        /// </summary>
        private static void DisplayHelp()
        {
            Console.WriteLine("Usage: SignInfo [-a] [-h] [-i] filename");
            Console.WriteLine();
            Console.WriteLine("  -a         Show extended version information");
            Console.WriteLine("  -h         Show file hashes");
            Console.WriteLine("  -i         Show signing chain");
            Console.WriteLine("  -nobanner  Quiet (no banner)");
            Console.WriteLine("  --help     Show this help information");
            Console.WriteLine();
        } // DisplayHelp()

        /// <summary>
        /// Processes the argument.
        /// </summary>
        /// <param name="args">The arguments.</param>
        /// <param name="index">The index.</param>
        /// <returns>The index of the next argument to process.</returns>
        private int ProcessArgument(IReadOnlyList<string> args, int index)
        {
            if (args[index].ToUpperInvariant() == "-A")
            {
                this.ShowExtendedVersionInfo = true;
                return index + 1;
            } // if

            if (args[index].ToUpperInvariant() == "-H")
            {
                this.ShowFileHashes = true;
                return index + 1;
            } // if

            if (args[index].ToUpperInvariant() == "--HELP")
            {
                this.ShowHelp = true;
                return index + 1;
            } // if

            if (args[index].ToUpperInvariant() == "-I")
            {
                this.ShowSigningChain = true;
                return index + 1;
            } // if

            if (args[index].ToUpperInvariant() == "-NOBANNER")
            {
                this.NoBanner = true;
                return index + 1;
            } // if

            // if it is no other known argument, it must be the file spec
            this.FileSpec = args[index];
            return index + 99;
        } // ProcessArgument()

        /// <summary>
        /// Parses the command line.
        /// </summary>
        /// <param name="args">The arguments.</param>
        /// <returns><c>false</c> if there is a severe problem; otherwise <c>true</c>.</returns>
        private bool ParseCommandLine(IReadOnlyList<string> args)
        {
            if (args.Count < 1)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Insufficient number of arguments!");
                Console.ForegroundColor = this.backupColor;
                return false;
            } // if

            var index = 0;
            while (index < args.Count)
            {
                index = this.ProcessArgument(args, index);
            } // while

            return true;
        } // ParseCommandLine()
#endregion // PRIVATE METHODS
    } // SignInfo
}
