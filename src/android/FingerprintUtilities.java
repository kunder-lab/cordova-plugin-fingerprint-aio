package de.niklasmerz.cordova.fingerprint;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@TargetApi(Build.VERSION_CODES.M)
public class FingerprintUtilities {
    private static final String KEY_STORE = "AndroidKeyStore";
    private static final String KEY_IV = "IV";
    private static final String TAG = "FingerprintUtilities";
    private static SharedPreferences mSharedPreferences = null;

    private void initSharedPreferences(Context context) {
        if(mSharedPreferences == null) {
            String domain = getDomain(context);
            mSharedPreferences = context.getSharedPreferences(domain, Context.MODE_PRIVATE);
        }
    }
    private String getDomain(Context context) {
        String packageName = context.getPackageName();
        int dotPos = packageName.indexOf(".");
        dotPos = packageName.indexOf(".",dotPos+1);
        return packageName.substring(0, dotPos);
    }
    public KeyStore providesKeystore() throws KeyStoreException{
        return KeyStore.getInstance(KEY_STORE);
    }
    public KeyGenerator providesKeyGenerator() throws NoSuchAlgorithmException, NoSuchProviderException {
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEY_STORE);
    }
    public Cipher providesCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7
        );
    }
    public void setDataToSharedPreferences(Context context, String key, String value) {
        initSharedPreferences(context);
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.putString(key, value);
        editor.commit();
    }
    public String getDataFromSharedPreferences(Context context, String key) {
        initSharedPreferences(context);
        return mSharedPreferences.getString(key, null);
    }
    public void deleteIVFromSharedPreferences(Context context) {
        initSharedPreferences(context);
        SharedPreferences.Editor editor = mSharedPreferences.edit();
        editor.remove(KEY_IV);
        editor.commit();
    }

    public String encryptWithCipher(Context context, Cipher cipher, String data) throws BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException {
        Log.i(TAG, "encryptWithCipher called");
        byte[] encryptedData = cipher.doFinal(data.getBytes());

        IvParameterSpec ivParams = cipher.getParameters().getParameterSpec(IvParameterSpec.class);
        String iv = Base64.encodeToString(ivParams.getIV(), Base64.DEFAULT);

        setDataToSharedPreferences(context, KEY_IV, iv);

        Log.i(TAG, "IV saved: "+iv);
        Log.i(TAG, "Message to encrypt: "+data);
        return Base64.encodeToString(encryptedData, Base64.DEFAULT);
    }

    public String decryptWithCipher(Cipher cipher, String encryptedData) throws BadPaddingException, IllegalBlockSizeException{
        byte[] encodedData = Base64.decode(encryptedData, Base64.DEFAULT);
        byte[] decodedData = cipher.doFinal(encodedData);
        return new String(decodedData);
    }

    public Cipher initCipher(int mode, Context context, SecretKey secretKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {

        Cipher cipher = providesCipher();

        if(mode == Cipher.ENCRYPT_MODE) {
            cipher.init(mode, secretKey);

        } else if(mode == Cipher.DECRYPT_MODE){
            byte[] iv = Base64.decode(getDataFromSharedPreferences(context, KEY_IV), Base64.DEFAULT);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(mode, secretKey, ivParameterSpec);
        }
        return cipher;
    }
    public SecretKey getSecretKey(String keyName, boolean disableBackup) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, UnrecoverableKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyStore keyStore = providesKeystore();
        keyStore.load(null);
        SecretKey secretKey = (SecretKey) keyStore.getKey(keyName, null);
        if(secretKey == null) {
            return createSecretKey(keyName, disableBackup);
        }
        return secretKey;
    }

    public SecretKey createSecretKey(String keyName, boolean disableBackup) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        KeyGenerator keyGenerator = providesKeyGenerator();
        keyGenerator.init(new KeyGenParameterSpec.Builder(keyName,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setUserAuthenticationRequired(disableBackup)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build()
        );
        return keyGenerator.generateKey();
    }

    public void deleteSecretKey(String keyName) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException {
        KeyStore keyStore = providesKeystore();
        keyStore.load(null);
        keyStore.deleteEntry(keyName);
    }

    public boolean isFingerprintAuthAvailable(Context context) {
        FingerprintManager fingerprintManager = context.getSystemService(FingerprintManager.class);
        return fingerprintManager.isHardwareDetected()
                && fingerprintManager.hasEnrolledFingerprints();
    }

    public boolean hasEnrolledFingerprints(Context context) {
        FingerprintManager fingerprintManager = context.getSystemService(FingerprintManager.class);
        return fingerprintManager.isHardwareDetected() && !(fingerprintManager.hasEnrolledFingerprints());
    }
}
