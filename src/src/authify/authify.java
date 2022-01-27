package authify;

import com.roxstudio.utils.CUrl; // https requests

import com.sun.security.auth.module.NTSystem;//user sid aka hwid

import org.json.JSONObject; // response decoding

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
// encryption stuff

import javax.swing.*; //messagebox

import java.awt.*;
import java.net.URI;
//desktop open link

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
// hash

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
// PKCS7 padding

import java.util.Date;// date utils

import java.util.UUID; // iv key

/*
needed dependencies :
java curl by rockswang
bouncy.castle bcprov
org.json json
*/
class api {
    public String program_version, program_key, api_key;

    private boolean is_initialized, show_messages, logged_in;

    public api(String version, String program_key, String api_key) {
        this.program_version = version;

        this.program_key = program_key;

        this.api_key = api_key;

        this.show_messages = true;
    }

    public api(String version, String program_key, String api_key, boolean show_messages){
        this.program_version = version;

        this.program_key = program_key;

        this.api_key = api_key;

        this.show_messages = show_messages;
    }

    private String session_id, session_iv;

    public void init() {
        try {
            session_iv = encryption.iv_key();

            var init_iv = encryption.sha256(session_iv);

            var post_data =
                    "version=" + encryption.encrypt(program_version, api_key, init_iv) +
                    "&session_iv=" + encryption.encrypt(session_iv, api_key, init_iv) +
                    "&api_version=" + encryption.encrypt("1.2", api_key, init_iv) +
                    "&program_key=" + encryption.byte_arr_to_str(program_key.getBytes()) +
                    "&init_iv=" + init_iv;

            var response = do_request("init", post_data);

            if (response.equals("program_doesnt_exist")) {
                messagebox.show("The program key you tried to use doesn't exist", messagebox.icons.error);

                return;
            }

            response = encryption.decrypt(response, api_key, init_iv);

            var decoded_response = new JSONObject(response);

            if (!decoded_response.getBoolean("success"))
                messagebox.show(decoded_response.getString("message"), messagebox.icons.error);

            var response_data = decoded_response.getString("response").split("\\|");

            if (response_data[0].equals("wrong_version")) {
                if (Desktop.isDesktopSupported())
                    Desktop.getDesktop().browse(new URI(response_data[1]));

                return;
            }

            is_initialized = true;

            session_iv += response_data[1];

            session_id = response_data[2];

        } catch (Exception ignored) { }
    }

    public boolean login(String username, String password){
        var hwid = new NTSystem().getUserSID();

        if (!is_initialized) {
            messagebox.show("The program wasn't initialized", messagebox.icons.error);

            return false;
        }

        var post_data =
                "username=" + encryption.encrypt(username, api_key, session_iv) +
                "&password=" + encryption.encrypt(password, api_key, session_iv) +
                "&hwid=" + encryption.encrypt(hwid, api_key, session_iv) +
                "&sessid=" + encryption.byte_arr_to_str(session_id.getBytes());

        var response = do_request("login", post_data);

        response = encryption.decrypt(response, api_key, session_iv);

        var decoded_response = new JSONObject(response);
        
        logged_in = decoded_response.getBoolean("success");

        if (!logged_in && show_messages)
            messagebox.show(decoded_response.getString("message"), messagebox.icons.error);
        else if(logged_in)
            load_user_data(decoded_response.getJSONObject("user_data"));

        stored_pass = (logged_in) ? password : null;

        return logged_in;
    }

    public boolean register(String username, String email, String password, String token) {
        var hwid = new NTSystem().getUserSID();

        if (!is_initialized) {
            messagebox.show("The program wasn't initialized", messagebox.icons.error);

            return false;
        }

        var post_data =
                "username=" + encryption.encrypt(username, api_key, session_iv) +
                "&email=" + encryption.encrypt(email, api_key, session_iv) +
                "&password=" + encryption.encrypt(password, api_key, session_iv) +
                "&token=" + encryption.encrypt(token, api_key, session_iv) +
                "&hwid=" + encryption.encrypt(hwid, api_key, session_iv) +
                "&sessid=" + encryption.byte_arr_to_str(session_id.getBytes());

        var response = do_request("register", post_data);

        response = encryption.decrypt(response, api_key, session_iv);

        var decoded_response = new JSONObject(response);

        if (!decoded_response.getBoolean("success") && show_messages)
            messagebox.show(decoded_response.getString("message"), messagebox.icons.error);

        return decoded_response.getBoolean("success");
    }

    public boolean activate(String username, String token) {
        if (!is_initialized) {
            messagebox.show("The program wasn't initialized", messagebox.icons.error);

            return false;
        }

        var post_data =
                "username=" + encryption.encrypt(username, api_key, session_iv) +
                "&token=" + encryption.encrypt(token, api_key, session_iv) +
                "&sessid=" + encryption.byte_arr_to_str(session_id.getBytes());

        var response = do_request("activate", post_data);

        response = encryption.decrypt(response, api_key, session_iv);

        var decoded_response = new JSONObject(response);

        if (!decoded_response.getBoolean("success") && show_messages)
            messagebox.show(decoded_response.getString("message"), messagebox.icons.error);

        return decoded_response.getBoolean("success");
    }

    public boolean all_in_one(String token) {
        if (login(token, token))
            return true;

        else if (register(token, token + "@email.com", token, token)) {
            System.exit(0);
            return true;
        }

        return false;
    }

    private String stored_pass;

    public byte[] file(String file_name){
        var hwid = new NTSystem().getUserSID();

        if (!is_initialized) {
            messagebox.show("The program wasn't initialized", messagebox.icons.error);

            return "not_initialized".getBytes();
        }

        if (!logged_in) {
            messagebox.show("You can only grab server sided files after being logged in.", messagebox.icons.error);

            return "not_logged_in".getBytes();
        }

        var post_data =
                "file_name=" + encryption.encrypt(file_name, api_key, session_iv) +
                "&username=" + encryption.encrypt(user_data.username, api_key, session_iv) +
                "&password=" + encryption.encrypt(stored_pass, api_key, session_iv) +
                "&hwid=" + encryption.encrypt(hwid, api_key, session_iv) +
                "&sessid=" + encryption.byte_arr_to_str(session_id.getBytes());

        var response = do_request("file", post_data);

        response = encryption.decrypt(response, api_key, session_iv);

        var decoded_response = new JSONObject(response);

        if (!decoded_response.getBoolean("success") && show_messages)
            messagebox.show(decoded_response.getString("message"), messagebox.icons.error);

        return encryption.str_to_byte_arr(decoded_response.getString("response"));
    }

    public String var(String var_name) {
        var hwid = new NTSystem().getUserSID();

        if (!is_initialized) {
            messagebox.show("The program wasn't initialized", messagebox.icons.error);

            return "not_initialized";
        }

        if (!logged_in) {
            messagebox.show("You can only grab server sided variables after being logged in.", messagebox.icons.error);

            return "not_logged_in";
        }

        var post_data =
                "var_name=" + encryption.encrypt(var_name, api_key, session_iv) +
                "&username=" + encryption.encrypt(user_data.username, api_key, session_iv) +
                "&password=" + encryption.encrypt(stored_pass, api_key, session_iv) +
                "&hwid=" + encryption.encrypt(hwid, api_key, session_iv) +
                "&sessid=" + encryption.byte_arr_to_str(session_id.getBytes());

        var response = do_request("var", post_data);

        response = encryption.decrypt(response, api_key, session_iv);

        var decoded_response = new JSONObject(response);

        if (!decoded_response.getBoolean("success") && show_messages)
            messagebox.show(decoded_response.getString("message"), messagebox.icons.error);

        return decoded_response.getString("response");
    }

    public void log(String message) {
        if (user_data.username == null || user_data.username.length() == 0) user_data.username = "NONE";

        if (!is_initialized) {
            messagebox.show("The program wasn't initialized", messagebox.icons.error);

            return;
        }

        var post_data =
                "username=" + encryption.encrypt(user_data.username, api_key, session_iv) +
                "&message=" + encryption.encrypt(message, api_key, session_iv) +
                "&sessid=" + encryption.byte_arr_to_str(session_id.getBytes());

        do_request("log", post_data);
    }

    private String do_request(String type, String post_data) {
        CUrl curl = new CUrl(api_endpoint + "?type=" + type)
                .data(post_data)
                .opt("-A", user_agent)
                .insecure();

        //TODO : add public key pinning

        return new String(curl.exec());
    }

    //region user_data
    public user_data_class user_data = new user_data_class();

    public class user_data_class {
        public String username, email, var;
        public int rank;
        public Date expires;
    }
    private void load_user_data(JSONObject data) {
        user_data.username = data.getString("username");

        user_data.email = data.getString("email");

        user_data.expires = new Date(Long.parseLong(data.getString("expires")));

        user_data.var = data.getString("var");

        user_data.rank = data.getInt("rank");
    }
    //endregion

    private String api_endpoint = "https://authify.biz/api/handler.php";

    private String user_agent = "Mozilla Authify";
}

class encryption{
    public static String byte_arr_to_str(byte[] ba) {
        StringBuilder hex = new StringBuilder(ba.length * 2);
        for (byte b : ba)
            hex.append(String.format("%02X", b));
        return hex.toString().toLowerCase();
    }

    public static byte[] str_to_byte_arr(String hex) {
        int NumberChars = hex.length();
        byte[] bytes = new byte[NumberChars / 2];
        for (int i = 0; i < NumberChars; i += 2)
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        return bytes;
    }

    public static String encrypt_string(String plain_text, byte[] key, byte[] iv) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        var aes = Cipher.getInstance("AES/CBC/PKCS7PADDING");

        aes.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new IvParameterSpec(iv)
        );

        var raw_bytes = aes.doFinal(plain_text.getBytes());

        return byte_arr_to_str(raw_bytes);
    }

    public static String decrypt_string(String cipher_text, byte[] key, byte[] iv) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        var str_bytes = str_to_byte_arr(cipher_text);

        var aes = Cipher.getInstance("AES/CBC/PKCS7PADDING");

        aes.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new IvParameterSpec(iv)
        );

        var out_string = aes.doFinal(str_bytes);

        return new String(out_string);
    }

    public static String encrypt(String message, String enc_key, String iv) {
        try {
            byte[] _key = sha256(enc_key).substring(0, 32).getBytes();

            byte[] _iv = sha256(iv).substring(0, 16).getBytes();

            return encrypt_string(message, _key, _iv);
        }
        catch(Exception ex){
            messagebox.show("Invalid API/Encryption key", messagebox.icons.error);

            return "";
        }
    }

    public static String decrypt(String message, String enc_key, String iv) {
        try {
            byte[] _key = sha256(enc_key).substring(0, 32).getBytes();

            byte[] _iv = sha256(iv).substring(0, 16).getBytes();

            return decrypt_string(message, _key, _iv);
        }
        catch(Exception ex){
            messagebox.show("Invalid API/Encryption key", messagebox.icons.error);

            return "";
        }
    }

    public static String sha256(String r) {
        try {
            return byte_arr_to_str(MessageDigest.getInstance("SHA-256").digest(r.getBytes()));
        }
        catch(NoSuchAlgorithmException never){
            return never.toString();
        }
    }

    static String iv_key(){
        return UUID.randomUUID().toString().substring(0, 8);
    }
}

class messagebox {
    public enum icons{
        warning(JOptionPane.WARNING_MESSAGE),
        info(JOptionPane.INFORMATION_MESSAGE),
        error(JOptionPane.ERROR_MESSAGE),
        none(JOptionPane.PLAIN_MESSAGE);

        icons(int i) {
            selected_icon = i;
        }

        public int selected_icon;
    }

    public static void show(String text, icons ico){
        JOptionPane.showMessageDialog(null, text, "Authify", ico.selected_icon);
    }
}