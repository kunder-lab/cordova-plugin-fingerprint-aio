/*
 * Copyright (C) https://github.com/mjwheatley/cordova-plugin-android-fingerprint-auth
 * Modifications copyright (C) 2016 Niklas Merz
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package de.niklasmerz.cordova.fingerprint;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.util.Log;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import android.os.Build;

@TargetApi(Build.VERSION_CODES.M)
public class Fingerprint extends CordovaPlugin {

    private static final String TAG = "Fingerprint";

    private static final String DIALOG_FRAGMENT_TAG = "FpAuthDialog";
    private static final String ENCRYPT_TYPE = "ENC";
    private static String INVALIDATED_KEY = "Key permanently invalidated";
    private static String INVALIDATED_KEY_MSG = "invalidatedKey";

    private static FingerprintAuthenticationDialogFragment mFragment = null;
    private static Context mContext;
    private static FingerprintUtilities fingerprintUtilities;
    public static String packageName;
    private static String publicKey;
    private static Cipher mCipher;
    private static CallbackContext mCallbackContext;
    private static PluginResult mPluginResult;

    private static String secretString = "";
    private static int cipherMode;
    private static boolean mDisableBackup = false;
    private static boolean shouldProcessSecretString = false;

    /**
     * Constructor.
     */
    public Fingerprint() {
    }

    /**
     * Sets the context of the Command. This can then be used to do things like
     * get file paths associated with the Activity.
     *
     * @param cordova The context of the main Activity.
     * @param webView The CordovaWebView Cordova is running in.
     */

    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        if (android.os.Build.VERSION.SDK_INT < 23) {
            return;
        }
        Log.v(TAG, "Init Fingerprint");
        packageName = cordova.getActivity().getApplicationContext().getPackageName();
        mPluginResult = new PluginResult(PluginResult.Status.NO_RESULT);
        fingerprintUtilities = new FingerprintUtilities();
    }

    /**
     * Executes the request and returns PluginResult.
     *
     * @param action          The action to execute.
     * @param args            JSONArry of arguments for the plugin.
     * @param callbackContext The callback id used when calling back into JavaScript.
     * @return A PluginResult object with a status and message.
     */
    public boolean execute(final String action,
                           JSONArray args,
                           CallbackContext callbackContext) throws JSONException {
        mContext = cordova.getActivity().getApplicationContext();

        Log.v(TAG, "Fingerprint action: " + action);
        mCallbackContext = callbackContext;
        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.e(TAG, "minimum SDK version 23 required");
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            mCallbackContext.error("minimum SDK version 23 required");
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }

        if (action.equals("authenticate")) {
            final JSONObject arg_object = args.getJSONObject(0);
            authenticateUser(arg_object);
            return true;
        } else if (action.equals("isAvailable")) {
            if (fingerprintUtilities.hasEnrolledFingerprints(mContext)) {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("noEnrolled");
            } else if (!fingerprintUtilities.isFingerprintAuthAvailable(mContext)) {
                mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                mCallbackContext.error("noFingerPrint");
            } else {
                mPluginResult = new PluginResult(PluginResult.Status.OK);
                mCallbackContext.success();
            }
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }
        return false;
    }

    private boolean authenticateUser(JSONObject arg_object) throws JSONException {
        if (!arg_object.has("publicKey")) {
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
            mCallbackContext.error("Missing required parameters");
            mCallbackContext.sendPluginResult(mPluginResult);
            return true;
        }

        publicKey = arg_object.getString("publicKey");
        String encryptionMode = null;
        if(arg_object.has("encryptType")) {
            encryptionMode = arg_object.getString("encryptType");
        }
        if(arg_object.has("secretString")) {
            secretString = arg_object.getString("secretString");
        } else {
            secretString = null;
        }

        cipherMode = ENCRYPT_TYPE.equals(encryptionMode) ||
                encryptionMode == null ||
                "".equals(encryptionMode) ? Cipher.ENCRYPT_MODE: Cipher.DECRYPT_MODE;
        shouldProcessSecretString = "".equals(secretString) || secretString == null ? false : true;

        if (arg_object.has("disableBackup")) {
            mDisableBackup = arg_object.getBoolean("disableBackup");
        }
        // Set language
        Resources res = cordova.getActivity().getResources();
        // Change locale settings in the app.
        DisplayMetrics dm = res.getDisplayMetrics();
        Configuration conf = res.getConfiguration();
        //Do not change locale
        res.updateConfiguration(conf, dm);

        final SecretKey secretKey = getSecretKey();

        if (secretKey != null) {
            cordova.getActivity().runOnUiThread(new Runnable() {
                public void run() {
                    // Set up the crypto object for later. The object will be authenticated by use
                    // of the fingerprint.
                    mFragment = new FingerprintAuthenticationDialogFragment();
                    Bundle bundle = new Bundle();
                    bundle.putBoolean("disableBackup", mDisableBackup);
                    mFragment.setArguments(bundle);

                    try {
                        if (initCipher(secretKey)) {
                            mFragment.setCancelable(false);
                            // Show the fingerprint dialog. The user has the option to use the fingerprint with
                            // crypto, or you can fall back to using a server-side verified password.
                            mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
                            mFragment.show(cordova.getActivity()
                                    .getFragmentManager(), DIALOG_FRAGMENT_TAG);
                        } else if(!mDisableBackup) {
                            mFragment.setCryptoObject(new FingerprintManager
                                    .CryptoObject(mCipher));
                            mFragment.setStage(FingerprintAuthenticationDialogFragment
                                    .Stage.NEW_FINGERPRINT_ENROLLED);
                            mFragment.show(cordova.getActivity().getFragmentManager(),
                                    DIALOG_FRAGMENT_TAG);
                        } else {
                            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
                            mCallbackContext.error("Failed to init Cipher and backup disabled.");
                            mCallbackContext.sendPluginResult(mPluginResult);
                        }
                    } catch (InvalidKeyException e) {
                        /***
                         * If initCipher throws this exception this plugin should delete the saved IV
                         * and the invalidated secret key. Finally this may return an "invalidatedKey"
                         * error to the main app.
                         * This will happen if the user register another fingerprint in the system
                         * The system invalidates every key in the keystore automatically
                         */
                        returnInvalidatedKeyError();
                    }
                }
            });
            mPluginResult.setKeepCallback(true);
        } else {
            mCallbackContext.sendPluginResult(mPluginResult);
        }
        return true;
    }

    private static void returnInvalidatedKeyError() {
        fingerprintUtilities.deleteIVFromSharedPreferences(mContext);
        try {
            fingerprintUtilities.deleteSecretKey(publicKey);
        } catch (Exception e1) {
            e1.printStackTrace();
        }
        mCallbackContext.error(INVALIDATED_KEY_MSG);
        mPluginResult = new PluginResult(PluginResult.Status.ERROR, INVALIDATED_KEY_MSG);
        mCallbackContext.sendPluginResult(mPluginResult);
    }

    private static boolean initCipher(SecretKey secretKey) throws InvalidKeyException {
        boolean cipherInitialized = false;
        try {
            mCipher = fingerprintUtilities.initCipher(cipherMode, mContext, secretKey);
            cipherInitialized = true;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            if (INVALIDATED_KEY.equals(e.getMessage())) {
                throw e;
            }
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return cipherInitialized;
    }

    private static SecretKey getSecretKey() {
        SecretKey secretKey = null;
        boolean isKeyCreated = false;
        String errorMessage = "";
        String errorPrefix = "Failed to create key: ";
        try {
            secretKey = fingerprintUtilities.getSecretKey(publicKey, mDisableBackup);
            isKeyCreated = true;
        } catch (KeyStoreException e) {
            errorMessage = errorPrefix + "KeyStoreException: " + e.toString();
        } catch (NoSuchAlgorithmException e) {
            errorMessage = errorPrefix + "NoSuchAlgorithmException: " + e.toString();
        } catch (CertificateException e) {
            errorMessage = errorPrefix + "CertificateException: " + e.toString();
        } catch (IOException e) {
            errorMessage = errorPrefix + "IOException: " + e.toString();
        } catch (UnrecoverableKeyException e) {
            errorMessage = errorPrefix + "UnrecoverableKeyException: " + e.toString();
        } catch (InvalidAlgorithmParameterException e) {
            errorMessage = errorPrefix + "InvalidAlgorithmParameterException: " + e.toString();
        } catch (NoSuchProviderException e) {
            errorMessage = errorPrefix + "NoSuchProviderException: " + e.toString();
        }
        if (!isKeyCreated) {
            Log.e(TAG, errorMessage);
        }
        return secretKey;
    }

    public static void onAuthenticated(boolean withFingerprint) {
        Log.i(TAG, "onAuthenticated");
        JSONObject resultJson = new JSONObject();
        String errorMessage = "";
        boolean createdResultJson = false;
        try {
            if (withFingerprint) {
                // If the user has authenticated with fingerprint, verify that using cryptography and
                // then return the encrypted token
                resultJson.put("authenticationType", "fingerprint");
                if(shouldProcessSecretString) {
                    String secretStringProcessed = finallyProcess();
                    Log.i(TAG, "onAuthenticated secretStringProcessed: " + secretStringProcessed);
                    resultJson.put("secretStringProcessed", secretStringProcessed);
                }

            } else {
                // Authentication happened with backup password.
                resultJson.put("authenticationType", "backup");
                if(shouldProcessSecretString) {
                    String secretStringProcessed = finallyProcess();
                    Log.i(TAG, "onAuthenticated secretStringProcessed: " + secretStringProcessed);
                    resultJson.put("secretStringProcessed", secretStringProcessed);
                }
            }
            createdResultJson = true;
        } catch(IllegalBlockSizeException e) {
            e.printStackTrace();
            returnInvalidatedKeyError();
            return;
        } catch (Exception e) {
            errorMessage = "badKey";
            Log.e(TAG, e.toString());
        }

        if (createdResultJson) {
            mCallbackContext.success(resultJson);
            mPluginResult = new PluginResult(PluginResult.Status.OK);
        } else {
            mCallbackContext.error(errorMessage);
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        }
        mCallbackContext.sendPluginResult(mPluginResult);
    }

    public static void onCancelled() {
        mCallbackContext.error("Cancelled");
        mPluginResult = new PluginResult(PluginResult.Status.ERROR, "Cancelled");
        mCallbackContext.sendPluginResult(mPluginResult);
    }

    private static String finallyProcess() throws BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException {
        Log.i(TAG, "finallyProcess called");
        Log.i(TAG, "Message to encrypt/decrypt: " + secretString);
        if (cipherMode == Cipher.ENCRYPT_MODE) {
            return fingerprintUtilities.encryptWithCipher(mContext, mCipher, secretString);
        } else {
            return fingerprintUtilities.decryptWithCipher(mCipher, secretString);
        }
    }
}
