using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace dotNetEncryptDecrypt.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        // GET api/values
        [HttpGet]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/values/5
        [HttpGet("{id}")]
        public ActionResult<string> Get(int id)
        {
            return "value";
        }

        // POST api/values
        [HttpPost]
        public ActionResult<IEnumerable<ResultStr>> Post([FromBody] PostValue value)
        {
            string rsaPubKey = "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFfYwuaorFmRybxnRwklhKhWd6nhXaH66Y7YTdN92miJb/WZ2AM1/iNYslr6s0dWuxXY7Woc0QdZKaQAPZ5WV26DzrC3d5iTsCp/xmwY2rLYXlE4Y8vzU/B0CxoV5h1i1uUBJLEDmXWOW5hWfnfCSMKigje07ot9hftHkaOZVs4tAgMBAAE=";
            string rsaPriKey = "MIICWgIBAAKBgFfYwuaorFmRybxnRwklhKhWd6nhXaH66Y7YTdN92miJb/WZ2AM1/iNYslr6s0dWuxXY7Woc0QdZKaQAPZ5WV26DzrC3d5iTsCp/xmwY2rLYXlE4Y8vzU/B0CxoV5h1i1uUBJLEDmXWOW5hWfnfCSMKigje07ot9hftHkaOZVs4tAgMBAAECgYA5GgVWub2OW12uwdNC9shMRCh0nLGoYNkAqUmtd9lIqk3Eb8QiEi6n+ze0O9HdRVtG0ENC/ohBJowStrVW/vjFcqKp1VxgIaL8zRyFMyaZNtAQP5UP20GOY5ZAvVNDra4G5hUAP5rKeKiIzYEpLPOlIIuUuXU6PodE5k7y/QDSYQJBAJYv06emh8fF3U1a8WqC0soBlNN1GQ3e8TDA2RhZH62cMIOpYN2oTMr5+i7qcYEm+rIgZqgwo5JI44oqjoRZbucCQQCVvRNvQawv8NliJoaOvC6Hvoa+m9IYXC4ziqYF1/txVkXL6raRkF8djVt8d5JnnHTKvCqJDWZhyGTRnoFSypvLAkAU9sAYmspBPIFTluoz7+b0g5v+mE3S/de08nZbS7V8Sl0LQ81do2x0uMgPXHJTkNlVm+g4efGbLcl1M9OI7eLpAkB4Q8VBPZDrbFlckK7QI2qH0kns+7/Rmu/sq7ZOyTsFu5IRhvGdlkQeuzM4k9z95NaVIm5TZ3TMoqP/DHy4H0zjAkA80zqCDL14kLRxg2p/akRCv6G1YEDb+Y24TB9dXtfZLTs8ihQTBvTVDhzzRVbaxJ9dpSE9l6wlKP6oZL000+vN";

            string temIV = "eXyeR9jk47FMEdLN";
            string temKey32 = "NHg3FaZzVMsYmdyjm39HY4EBZf9dwA2u";
            string loginID = "test";
            string AES_IV = loginID + temIV.Remove(0, loginID.Length);
            string key32 = loginID + temKey32.Remove(0, loginID.Length);

            var rsa = new EncHelper.RSAHelper(EncHelper.EncType.RSAType.RSA, Encoding.UTF8, rsaPriKey, rsaPubKey);

            ResultStr rs = new ResultStr();
            switch (value.encmode)
            {
                case 1:
                    rs.type = "RSA Encrypt";
                    rs.result = rsa.Encrypt(value.text);
                    break;
                case 2:
                    rs.type = "RSA Decrpty";
                    rs.result = rsa.Decrypt(value.text);
                    break;
                case 3:
                    rs.type = "AES Encrypt";
                    rs.result = EncHelper.RSAHelper.AES_Encrypt(value.text, key32);
                    break;
                case 4:
                    rs.type = "AES Decrypt";
                    rs.result = EncHelper.RSAHelper.AES_Decrypt(value.text, key32);
                    break;
                case 5:
                    rs.type = "Decrypt By AES from Angular";
                    rs.result = EncHelper.RSAHelper.DecryptByAES(value.text, key32, AES_IV);
                    break;
                default:
                    break;
            }

            
            return new ResultStr[] { rs };
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }

    public struct PostValue
    {
        public int encmode { get; set; }
        public string text { get; set; }
    }
    public struct ResultStr
    {
        public string type { get; set; }
        public string result { get; set; }
    }
}
