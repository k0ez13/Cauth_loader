using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Specialized;
using System.Text;
using System.Net;
using System.IO;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Diagnostics;
using System.Security.Principal;

namespace c_auth
{
    public class api
    {
        public string program_version, program_key, api_key;

        private bool is_initialized, show_messages, logged_in;
        public api(string version, string program_key, string api_key, bool show_messages = true)
        {
            this.program_version = version;

            this.program_key = program_key;

            this.api_key = api_key;

            this.show_messages = show_messages;
        }

        #region structures
        [DataContract]
        private class response_structure
        {
            [DataMember]
            public bool success { get; set; }

            [DataMember]
            public string response { get; set; }

            [DataMember]
            public string message { get; set; }

            [DataMember(IsRequired = false, EmitDefaultValue = false)]
            public user_data_structure user_data { get; set; }
        }

        [DataContract]
        private class user_data_structure
        {
            [DataMember]
            public string username { get; set; }

            [DataMember]
            public string email { get; set; }

            [DataMember]
            public string expires { get; set; } //timestamp

            [DataMember]
            public string var { get; set; }

            [DataMember]
            public int rank { get; set; }
        }
        #endregion

        private string session_id, session_iv;
        public void init()
        {
            try
            {
                session_iv = encryption.iv_key();

                var init_iv = encryption.sha256(session_iv); // can be changed to whatever you want

                var values_to_upload = new NameValueCollection
                {
                    ["version"] = encryption.encrypt(program_version, api_key, init_iv),
                    ["session_iv"] = encryption.encrypt(session_iv, api_key, init_iv),
                    ["api_version"] = encryption.encrypt("1.1", api_key, init_iv),

                    ["program_key"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(program_key)),
                    ["init_iv"] = init_iv
                };

                var response = do_request("init", values_to_upload);

                if (response == "program_doesnt_exist")
                {
                    messagebox.show("The program key you tried to use doesn't exist", messagebox.icons.error);

                    return;
                }

                response = encryption.decrypt(response, api_key, init_iv);

                var decoded_response = response_decoder.string_to_generic<response_structure>(response);

                if (!decoded_response.success)
                    messagebox.show(decoded_response.message, messagebox.icons.error);

                var response_data = decoded_response.response.Split('|');

                if (response_data[0] == "wrong_version")
                {
                    Process.Start(response_data[1]);

                    return;
                }

                is_initialized = true;

                session_iv += response_data[1];

                session_id = response_data[2];
            }
            catch (CryptographicException)
            {
                messagebox.show("Invalid API/Encryption key", messagebox.icons.error);

                return;
            }
        }

        public bool login(string username, string password, string hwid = null)
        {
            if (hwid == null) hwid = WindowsIdentity.GetCurrent().User.Value;

            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return false;
            }

            var values_to_upload = new NameValueCollection
            {
                ["username"] = encryption.encrypt(username, api_key, session_iv),
                ["password"] = encryption.encrypt(password, api_key, session_iv),
                ["hwid"] = encryption.encrypt(hwid, api_key, session_iv),

                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            var response = do_request("login", values_to_upload);

            response = encryption.decrypt(response, api_key, session_iv);

            var decoded_response = response_decoder.string_to_generic<response_structure>(response);

            logged_in = decoded_response.success;

            if (!logged_in && show_messages)
                messagebox.show(decoded_response.message, messagebox.icons.error);
            else if (logged_in)
                load_user_data(decoded_response.user_data);

            stored_pass = (logged_in) ? password : null;

            return logged_in;
        }

        public bool register(string username, string email, string password, string token, string hwid = null)
        {
            if (hwid == null) hwid = WindowsIdentity.GetCurrent().User.Value;

            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return false;
            }

            var values_to_upload = new NameValueCollection
            {
                ["username"] = encryption.encrypt(username, api_key, session_iv),
                ["email"] = encryption.encrypt(email, api_key, session_iv),
                ["password"] = encryption.encrypt(password, api_key, session_iv),
                ["token"] = encryption.encrypt(token, api_key, session_iv),
                ["hwid"] = encryption.encrypt(hwid, api_key, session_iv),

                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            var response = do_request("register", values_to_upload);

            response = encryption.decrypt(response, api_key, session_iv);

            var decoded_response = response_decoder.string_to_generic<response_structure>(response);

            if (!decoded_response.success && show_messages)
                messagebox.show(decoded_response.message, messagebox.icons.error);

            return decoded_response.success;
        }

        public bool activate(string username, string token)
        {
            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return false;
            }

            var values_to_upload = new NameValueCollection
            {
                ["username"] = encryption.encrypt(username, api_key, session_iv),
                ["token"] = encryption.encrypt(token, api_key, session_iv),

                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            var response = do_request("activate", values_to_upload);

            response = encryption.decrypt(response, api_key, session_iv);

            var decoded_response = response_decoder.string_to_generic<response_structure>(response);

            if (!decoded_response.success && show_messages)
                messagebox.show(decoded_response.message, messagebox.icons.error);

            return decoded_response.success;
        }

        public bool all_in_one(string token, string hwid = null)
        {
            if (hwid == null) hwid = WindowsIdentity.GetCurrent().User.Value;

            if (login(token, token, hwid))
                return true;

            else if (register(token, token + "@email.com", token, token, hwid))
            {
                Environment.Exit(0);
                return true;
            }

            return false;
        }

        private string stored_pass;
        public string var(string var_name, string hwid = null)
        {
            if (hwid == null) hwid = WindowsIdentity.GetCurrent().User.Value;

            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return "not_initialized";
            }

            if (!logged_in)
            {
                messagebox.show("You can only grab server sided variables after being logged in.", messagebox.icons.error);

                return "not_logged_in";
            }

            var values_to_upload = new NameValueCollection
            {
                ["var_name"] = encryption.encrypt(var_name, api_key, session_iv),
                ["username"] = encryption.encrypt(user_data.username, api_key, session_iv),
                ["password"] = encryption.encrypt(stored_pass, api_key, session_iv),
                ["hwid"] = encryption.encrypt(hwid, api_key, session_iv),
                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            var response = do_request("var", values_to_upload);

            response = encryption.decrypt(response, api_key, session_iv);

            var decoded_response = response_decoder.string_to_generic<response_structure>(response);

            if (!decoded_response.success && show_messages)
                messagebox.show(decoded_response.message, messagebox.icons.error);

            return decoded_response.response;
        }

        public void log(string message)
        {
            if (user_data.username == null) user_data.username = "NONE";

            if (!is_initialized)
            {
                messagebox.show("The program wasn't initialized", messagebox.icons.error);

                return;
            }

            var values_to_upload = new NameValueCollection
            {
                ["username"] = encryption.encrypt(user_data.username, api_key, session_iv),
                ["message"] = encryption.encrypt(message, api_key, session_iv),
                ["sessid"] = encryption.byte_arr_to_str(Encoding.Default.GetBytes(session_id))
            };

            do_request("log", values_to_upload);
        }

        private string do_request(string type, NameValueCollection post_data)
        {
            using (WebClient client = new WebClient())
            {
                client.Headers["User-Agent"] = user_agent;

                ServicePointManager.ServerCertificateValidationCallback = others.pin_public_key;

                var raw_response = client.UploadValues(api_endpoint + "?type=" + type, post_data);

                ServicePointManager.ServerCertificateValidationCallback += (send, certificate, chain, sslPolicyErrors) => { return true; };

                return Encoding.Default.GetString(raw_response);
            }
        }

        #region user_data
        public user_data_class user_data = new user_data_class();

        public class user_data_class
        {
            public string username { get; set; }
            public string email { get; set; }
            public DateTime expires { get; set; }
            public string var { get; set; }
            public int rank { get; set; }
        }
        private void load_user_data(user_data_structure data)
        {
            user_data.username = data.username;

            user_data.email = data.email;

            user_data.expires = others.unix_to_date(Convert.ToDouble(data.expires));

            user_data.var = data.var;

            user_data.rank = data.rank;
        }
        #endregion

        private string api_endpoint = "https://cauth.me/api/handler.php";

        private string user_agent = "Mozilla cAuth";

        private json_wrapper response_decoder = new json_wrapper(new response_structure());
    }

    public static class others
    {
        public static DateTime unix_to_date(double unixTimeStamp) =>
    new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc).AddSeconds(unixTimeStamp).ToLocalTime();

        public static bool pin_public_key(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) =>
            certificate.GetPublicKeyString() == "3082010A0282010100C7429D4B4591E50FE4B3ABDA72DB3F3EA578E12B9CD4E228E4EDFAC3F9681F354C913386A13E88181D1B14D91723FB50770C5DC94FCA59D4DEE4F6632041EFE76C3B6BCFF6B8F5B38AF92547D04BD08AF71087B094F5DFE8760C8CD09A3771836807588B02282BEC7C4CD73EE7C650C0A7C7F36F2FA56DA17E892B2760C4C75950EA5C90CD4EA301EC0CBC36B8372FE8515A7131CC6DF13A97D95B94C6A92AC4E5BFF217FCB20B3C01DB085229E919555D426D919E9A9F0D4C599FE7473FA7DBDE9B33279E2FC29F6CE09FA1269409E4A82175C8E0B65723DB6F856A53E3FD11363ADD63D1346790A3E4D1E454D1714ECED9815A0F85C5019C0D4DC3D58234C10203010001";
    }

    public static class encryption
    {
        public static string byte_arr_to_str(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] str_to_byte_arr(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static string encrypt_string(string plain_text, byte[] key, byte[] iv)
        {
            Aes encryptor = Aes.Create();

            encryptor.Mode = CipherMode.CBC;
            encryptor.Key = key;
            encryptor.IV = iv;

            using (MemoryStream mem_stream = new MemoryStream())
            {
                using (ICryptoTransform aes_encryptor = encryptor.CreateEncryptor())
                {
                    using (CryptoStream crypt_stream = new CryptoStream(mem_stream, aes_encryptor, CryptoStreamMode.Write))
                    {
                        byte[] p_bytes = Encoding.Default.GetBytes(plain_text);

                        crypt_stream.Write(p_bytes, 0, p_bytes.Length);

                        crypt_stream.FlushFinalBlock();

                        byte[] c_bytes = mem_stream.ToArray();

                        return byte_arr_to_str(c_bytes);
                    }
                }
            }
        }

        public static string decrypt_string(string cipher_text, byte[] key, byte[] iv)
        {
            Aes encryptor = Aes.Create();

            encryptor.Mode = CipherMode.CBC;
            encryptor.Key = key;
            encryptor.IV = iv;

            using (MemoryStream mem_stream = new MemoryStream())
            {
                using (ICryptoTransform aes_decryptor = encryptor.CreateDecryptor())
                {
                    using (CryptoStream crypt_stream = new CryptoStream(mem_stream, aes_decryptor, CryptoStreamMode.Write))
                    {
                        byte[] c_bytes = str_to_byte_arr(cipher_text);

                        crypt_stream.Write(c_bytes, 0, c_bytes.Length);

                        crypt_stream.FlushFinalBlock();

                        byte[] p_bytes = mem_stream.ToArray();

                        return Encoding.Default.GetString(p_bytes, 0, p_bytes.Length);
                    }
                }
            }
        }

        public static string iv_key() =>
            Guid.NewGuid().ToString().Substring(0, Guid.NewGuid().ToString().IndexOf("-", StringComparison.Ordinal));

        public static string sha256(string r) =>
            byte_arr_to_str(new SHA256Managed().ComputeHash(Encoding.Default.GetBytes(r)));

        public static string encrypt(string message, string enc_key, string iv)
        {
            byte[] _key = Encoding.Default.GetBytes(sha256(enc_key).Substring(0, 32));

            byte[] _iv = Encoding.Default.GetBytes(sha256(iv).Substring(0, 16));

            return encrypt_string(message, _key, _iv);
        }

        public static string decrypt(string message, string enc_key, string iv)
        {
            byte[] _key = Encoding.Default.GetBytes(sha256(enc_key).Substring(0, 32));

            byte[] _iv = Encoding.Default.GetBytes(sha256(iv).Substring(0, 16));

            return decrypt_string(message, _key, _iv);
        }

        public static DateTime unix_to_date(double unixTimeStamp) =>
            new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc).AddSeconds(unixTimeStamp).ToLocalTime();

        public static bool pin_public_key(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) =>
            certificate.GetPublicKeyString() == "3082010A0282010100C7429D4B4591E50FE4B3ABDA72DB3F3EA578E12B9CD4E228E4EDFAC3F9681F354C913386A13E88181D1B14D91723FB50770C5DC94FCA59D4DEE4F6632041EFE76C3B6BCFF6B8F5B38AF92547D04BD08AF71087B094F5DFE8760C8CD09A3771836807588B02282BEC7C4CD73EE7C650C0A7C7F36F2FA56DA17E892B2760C4C75950EA5C90CD4EA301EC0CBC36B8372FE8515A7131CC6DF13A97D95B94C6A92AC4E5BFF217FCB20B3C01DB085229E919555D426D919E9A9F0D4C599FE7473FA7DBDE9B33279E2FC29F6CE09FA1269409E4A82175C8E0B65723DB6F856A53E3FD11363ADD63D1346790A3E4D1E454D1714ECED9815A0F85C5019C0D4DC3D58234C10203010001";
    }

    public static class messagebox
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern int MessageBox(IntPtr hWND, string message, string caption, uint icon);

        public enum icons : long
        {
            exclamation = 0x00000030L,
            warning = 0x00000030L,
            information = 0x00000040L,
            asterisk = 0x00000040L,
            question = 0x00000020L,
            stop = 0x00000010L,
            error = 0x00000010L,
            hand = 0x00000010L
        }

        public static int show(string text, icons ico)
        {
            return MessageBox((IntPtr)0, text, "cAuth", (uint)ico);
        }
    }

    public class json_wrapper
    {
        public static bool is_serializable(Type to_check) =>
            to_check.IsSerializable || to_check.IsDefined(typeof(DataContractAttribute), true);

        public json_wrapper(object obj_to_work_with)
        {
            current_object = obj_to_work_with;

            var object_type = current_object.GetType();

            serializer = new DataContractJsonSerializer(object_type);

            if (!is_serializable(object_type))
                throw new Exception($"the object {current_object} isn't a serializable");
        }

        public string to_json_string()
        {
            using (var mem_stream = new MemoryStream())
            {
                serializer.WriteObject(mem_stream, current_object);

                mem_stream.Position = 0;

                using (var reader = new StreamReader(mem_stream))
                    return reader.ReadToEnd();
            }
        }

        public object string_to_object(string json)
        {
            var buffer = Encoding.Default.GetBytes(json);

            //SerializationException = session expired

            using (var mem_stream = new MemoryStream(buffer))
                return serializer.ReadObject(mem_stream);
        }

        #region extras

        public dynamic string_to_dynamic(string json) =>
            (dynamic)string_to_object(json);

        public T string_to_generic<T>(string json) =>
            (T)string_to_object(json);

        public dynamic to_json_dynamic() =>
            string_to_object(to_json_string());

        #endregion

        private DataContractJsonSerializer serializer;

        private object current_object;
    }
}
