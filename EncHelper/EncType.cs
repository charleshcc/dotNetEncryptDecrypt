using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace dotNetEncryptDecrypt.EncHelper
{
    public class EncType
    {
        public enum RSAType
        {
            /// <summary>
            /// SHA1
            /// </summary>
            RSA = 0,
            /// <summary>
            /// RSA2 key length is at least 2048
            /// SHA256
            /// </summary>
            RSA2
        }
    }
}
