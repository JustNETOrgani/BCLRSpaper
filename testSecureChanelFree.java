import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import it.unisa.dia.gas.jpbc.Element;

public class testSecureChanelFree {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        secureChanelFree scf = new secureChanelFree();
        // Run setup algorithm.
        scf.setup();
        // Sample User ID.
        String userID = "justnetorgani@github.com";
         // Set Time main bound T_M.
         int T_M = 30;
        // Set user public params.
        ArrayList<userPublicValues> userPubVals = scf.setSecretValue(userID,T_M);
        System.out.println("============ User Public Parameters ==============");
        System.out.println("userID: "+ userID);
        //System.out.println("Y_i: "+ Y_i);
        System.out.println("============== User Public Parameters ===============");

        // Trusted entity sets designated user's key.
        ArrayList<designatedUserParamSCF> designatedUserPubParams = scf.partialPrivateKeyExtract(userID, userPubVals, T_M);

        // Designated user runs key extract.
        int T_D = 15;
        Element[] userKeys = scf.setPrivateKey(designatedUserPubParams, userID, T_M, T_D);
        if (userKeys.length>1){
            System.out.println("============ User Private/Public Keys ==============");
            System.out.println("Extracted Partial private key: "+ userKeys[1]);
            System.out.println("User secret value: "+ userKeys[0]);
            System.out.println("User Ephemeral secret key: "+ userKeys[2]);
            // Set Public Key.
            ArrayList<userPubKey> pubKey = scf.setPubKey(userID, designatedUserPubParams, T_M);
            System.out.println("Public key (Q_ID_i): "+ pubKey.get(0).Q_ID_i);
            System.out.println("Public key (Y_i): "+ pubKey.get(0).Y_i);
            System.out.println("============== User Private/Public Keys  ===============");
            // Generate ring signature.
            String[] L = {"hi@qq.com", userID, "security@outlook.com", "ytx@qq.com"};
            String ev = "BCSCFFSKI-SBv-2024";
            // Create sample messages.
            String msg = "RS with JPBC";
            String fakeMsg = "RS with no JPBC";
            String[] msgs = {msg, fakeMsg};
            ArrayList<signatureVals> sigVals = scf.ringSign(ev, L, userKeys[2], userKeys[0], msgs[0], T_D,pubKey);
            // Verify ring signature...Test with correct and tampered msg.
            for (int i = 0; i < msgs.length; i++) { 
                boolean verifResult = scf.ringVerify(sigVals, L, msgs[i], ev, T_D);
            if (verifResult==true){
                System.out.println("============ Signature Verifcation on the message: " + msgs[i] + " ==============");
                System.out.println("VerifResult: "+ verifResult);
                System.out.println("Verification passed.");
                System.out.println("========================= Signature Verifcation done ============================");
                System.out.println("");
            }
            else {
                System.out.println("============ Signature Verifcation on the message: " + msgs[i] + " ==============");
                System.out.println("VerifResult: "+ verifResult);
                System.out.println("Verification failed.");
                System.out.println("========================= Signature Verifcation done ============================");
            }
            }
        } else {
            System.out.println("Ooops! Execution error.");
        }
        
    }

}
