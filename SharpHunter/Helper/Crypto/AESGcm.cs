using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SharpHunter.Utils
{
   //AES GCM from https://github.com/dvsekhvalnov/jose-jwt
    internal class AesGcm
    {
        public byte[] Decrypt(byte[] key, byte[] iv, byte[] aad, byte[] cipherText, byte[] authTag)
        {
            IntPtr hAlg = OpenAlgorithmProvider(Win32.BCRYPT_AES_ALGORITHM, Win32.MS_PRIMITIVE_PROVIDER, Win32.BCRYPT_CHAIN_MODE_GCM);
            var keyDataBuffer = ImportKey(hAlg, key, out var hKey);

            byte[] plainText;

            Win32.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = new Win32.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, aad, authTag);
            byte[] ivData = new byte[MaxAuthTagSize(hAlg)];

            int plainTextSize = 0;

            uint status = Win32.BCryptDecrypt(hKey, cipherText, cipherText.Length, ref authInfo, ivData, ivData.Length, null, 0, ref plainTextSize, 0x0);

            if (status != Win32.ERROR_SUCCESS)
                throw new CryptographicException(
                    $"Win32.BCryptDecrypt() (get size) failed with status code: {status}");

            plainText = new byte[plainTextSize];

            status = Win32.BCryptDecrypt(hKey, cipherText, cipherText.Length, ref authInfo, ivData, ivData.Length, plainText, plainText.Length, ref plainTextSize, 0x0);

            if (status == Win32.STATUS_AUTH_TAG_MISMATCH)
                throw new CryptographicException("Win32.BCryptDecrypt(): authentication tag mismatch");

            if (status != Win32.ERROR_SUCCESS)
                throw new CryptographicException($"Win32.BCryptDecrypt() failed with status code:{status}");

            authInfo.Dispose();

            Win32.BCryptDestroyKey(hKey);
            Marshal.FreeHGlobal(keyDataBuffer);
            Win32.BCryptCloseAlgorithmProvider(hAlg, 0x0);

            return plainText;
        }

        private int MaxAuthTagSize(IntPtr hAlg)
        {
            byte[] tagLengthsValue = GetProperty(hAlg, Win32.BCRYPT_AUTH_TAG_LENGTH);

            return BitConverter.ToInt32(new[] { tagLengthsValue[4], tagLengthsValue[5], tagLengthsValue[6], tagLengthsValue[7] }, 0);
        }

        private IntPtr OpenAlgorithmProvider(string alg, string provider, string chainingMode)
        {
            uint status = Win32.BCryptOpenAlgorithmProvider(out var hAlg, alg, provider, 0x0);

            if (status != Win32.ERROR_SUCCESS)
                throw new CryptographicException(
                    $"Win32.BCryptOpenAlgorithmProvider() failed with status code:{status}");

            byte[] chainMode = Encoding.Unicode.GetBytes(chainingMode);
            status = Win32.BCryptSetAlgorithmProperty(hAlg, Win32.BCRYPT_CHAINING_MODE, chainMode, chainMode.Length, 0x0);

            if (status != Win32.ERROR_SUCCESS)
                throw new CryptographicException(
                    $"Win32.BCryptSetAlgorithmProperty(Win32.BCRYPT_CHAINING_MODE, Win32.BCRYPT_CHAIN_MODE_GCM) failed with status code:{status}");

            return hAlg;
        }

        private IntPtr ImportKey(IntPtr hAlg, byte[] key, out IntPtr hKey)
        {
            byte[] objLength = GetProperty(hAlg, Win32.BCRYPT_OBJECT_LENGTH);

            int keyDataSize = BitConverter.ToInt32(objLength, 0);

            IntPtr keyDataBuffer = Marshal.AllocHGlobal(keyDataSize);

            byte[] keyBlob = Concat(Win32.BCRYPT_KEY_DATA_BLOB_MAGIC, BitConverter.GetBytes(0x1), BitConverter.GetBytes(key.Length), key);

            uint status = Win32.BCryptImportKey(hAlg, IntPtr.Zero, Win32.BCRYPT_KEY_DATA_BLOB, out hKey, keyDataBuffer, keyDataSize, keyBlob, keyBlob.Length, 0x0);

            if (status != Win32.ERROR_SUCCESS)
                throw new CryptographicException($"Win32.BCryptImportKey() failed with status code:{status}");

            return keyDataBuffer;
        }

        private byte[] GetProperty(IntPtr hAlg, string name)
        {
            int size = 0;

            uint status = Win32.BCryptGetProperty(hAlg, name, null, 0, ref size, 0x0);

            if (status != Win32.ERROR_SUCCESS)
                throw new CryptographicException(
                    $"Win32.BCryptGetProperty() (get size) failed with status code:{status}");

            byte[] value = new byte[size];

            status = Win32.BCryptGetProperty(hAlg, name, value, value.Length, ref size, 0x0);

            if (status != Win32.ERROR_SUCCESS)
                throw new CryptographicException($"Win32.BCryptGetProperty() failed with status code:{status}");

            return value;
        }

        public byte[] Concat(params byte[][] arrays)
        {
            int len = 0;

            foreach (byte[] array in arrays)
            {
                if (array == null)
                    continue;
                len += array.Length;
            }

            byte[] result = new byte[len - 1 + 1];
            int offset = 0;

            foreach (byte[] array in arrays)
            {
                if (array == null)
                    continue;
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }

            return result;
        }
    }
}
