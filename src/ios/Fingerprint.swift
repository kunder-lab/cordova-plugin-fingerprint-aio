import Foundation
import LocalAuthentication

private var authenticationContext = LAContext();

@objc(Fingerprint) class Fingerprint : CDVPlugin {
    
    func isAvailable(_ command: CDVInvokedUrlCommand){
        authenticationContext = LAContext();
        var error:NSError?;
        var errorString = "";
        let available = authenticationContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error);
        
        var pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: "OK");
        
        if available == false {
            switch error!.code {
            case LAError.touchIDNotAvailable.rawValue:
                errorString = "noFingerPrint"
                break;
            case LAError.touchIDNotEnrolled.rawValue:
                errorString = "noEnrolled"
                break;
            case LAError.passcodeNotSet.rawValue:
                errorString = "noPassCode"
                break;
            default:
                errorString = "errorAuth"
                if #available(iOS 9.0, *) {
                    if (error!.code == LAError.touchIDLockout.rawValue) {
                        errorString = "blocked";
                    }
                }
            }
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorString);
        }
        
        commandDelegate.send(pluginResult, callbackId:command.callbackId);
    }
    
    func authenticate(_ command: CDVInvokedUrlCommand){
        authenticationContext = LAContext();
        var pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "Something went wrong");
        var reason = "Authentication";
        let data  = command.arguments[0] as AnyObject?;
        
        if let description = data?["description"] as! String? {
            reason = description;
        }
        authenticationContext.localizedFallbackTitle = "";
        
        authenticationContext.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason,
            reply: { [unowned self] (success, error) -> Void in
                if( success ) {
                    pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: "Success");
                }else {
                    var errorString = "";
                    
                    switch error!._code {
                    case LAError.touchIDNotAvailable.rawValue:
                        errorString = "noFingerPrint"
                        break;
                    case LAError.touchIDNotEnrolled.rawValue:
                        errorString = "noEnrolled"
                        break;
                    case LAError.passcodeNotSet.rawValue:
                        errorString = "noPassCode"
                        break;
                    case LAError.authenticationFailed.rawValue:
                        errorString = "authenticationFailed"
                        break;
                    case LAError.systemCancel.rawValue:
                        errorString = "cancelled"
                        break;
                    default:
                        errorString = "errorAuth"
                        if #available(iOS 9.0, *) {
                            if (error!._code == LAError.touchIDLockout.rawValue) {
                                errorString = "blocked";
                            }
                            else if(error!._code == LAError.appCancel.rawValue) {
                                errorString = "cancelled";
                            }
                        }
                    }
                    if error != nil {
                        pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorString);
                    }
                }
                self.commandDelegate.send(pluginResult, callbackId:command.callbackId);
        });
    }
}
