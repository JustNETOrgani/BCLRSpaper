import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class secureChanelFree {
    private cryptoParams cryptoParam;       // Public Key Parameters.
    private Element xInv;                   // Master Secret Key.
    public Element X;                       // Master Public Key.
    private Element u_i;                    // User secret value.

    public void setup(){
        // Setup must be run only once:
        if (cryptoParam != null && xInv != null) {
            System.out.println("Setup already executed!");
            return;
        }
        // Initialise Pairing and its Parameters:
        cryptoParam = new cryptoParams();
        cryptoParam.pairing = PairingFactory.getPairing("params.properties"); // Get parameters from file.

        // For ease of use. Returns random elements.
        cryptoParam.G1 = cryptoParam.pairing.getG1();
        cryptoParam.Gt = cryptoParam.pairing.getGT();
        cryptoParam.Zr = cryptoParam.pairing.getZr();
        cryptoParam.G  = cryptoParam.G1.newRandomElement().getImmutable(); // This acts as random generator.

        // Set master secret/private key x = random with Zr. Set x^-1 as private key.
        xInv = (cryptoParam.Zr.newRandomElement().invert()).getImmutable();

        // Set Master Public Key. X = xG
        X = (cryptoParam.G.duplicate()).mulZn(xInv).getImmutable();

        // Display public values.
        printStatements();
    }

    public ArrayList<userPublicValues> setSecretValue(String userID, int T_M) throws NoSuchAlgorithmException{
        // Choose secret value u_i and random value v.
        u_i = cryptoParam.Zr.newRandomElement().getImmutable();
        Element v = cryptoParam.Zr.newRandomElement();
        // Computes public values.
        // Initialise elements:
        userPublicValues userPublicElements = new userPublicValues();
        userPublicElements.U_ID_i = (cryptoParam.G.duplicate()).mulZn(u_i);
        userPublicElements.Q_ID_i = cryptoParam.G1.newRandomElement();
        String prepHash_1 = userID + T_M;
        hashFunc(userPublicElements.Q_ID_i, prepHash_1);
        userPublicElements.V_ID_i = ((userPublicElements.Q_ID_i.duplicate()).getImmutable()).mulZn(u_i.mulZn(v));
        userPublicElements.W_ID_i = (cryptoParam.G.duplicate()).mulZn(u_i.mulZn(v));
        // Prepare arrayList for return statement.
        ArrayList<userPublicValues> userPublicVals = new ArrayList<>();
        userPublicVals.add(userPublicElements);
        printUserPublicVals(userPublicVals);
        return userPublicVals;
    }

    public ArrayList<designatedUserParamSCF> partialPrivateKeyExtract(String userID, ArrayList<userPublicValues> userPubVals, int T_M) throws NoSuchAlgorithmException{
        // Equation check.
        Element outLeft = cryptoParam.pairing.pairing(userPubVals.get(0).V_ID_i.duplicate(), cryptoParam.G.duplicate());
        Element outRight = cryptoParam.pairing.pairing(userPubVals.get(0).Q_ID_i.duplicate(), userPubVals.get(0).W_ID_i.duplicate());
        if (outLeft.isEqual(outRight)){
            System.out.println("User check by KGC passed.");
             // Initialise elements:
            designatedUserParamSCF userSpecificParams = new designatedUserParamSCF();
            Element D_i =((userPubVals.get(0).Q_ID_i.duplicate()).getImmutable()).mulZn(xInv);
            System.out.println("============ User Private data ==============");
            System.out.println("Partial private key from KGC: "+D_i);
            System.out.println("============ User Private data ==============");
            Element R_ID_i = (userPubVals.get(0).U_ID_i.duplicate()).mulZn(xInv);
            userSpecificParams.s = cryptoParam.Zr.newElement();
            String prepHash_3 = userID + T_M + R_ID_i;
            hashFunc(userSpecificParams.s, prepHash_3);
            userSpecificParams.Y_ID_i = cryptoParam.G1.newElement();
            // Equation 1.
            userSpecificParams.Y_ID_i= (R_ID_i.sub(D_i)).add(userPubVals.get(0).U_ID_i.duplicate().mulZn(xInv.mulZn(userSpecificParams.s)));
            userSpecificParams.U_ID_i = userPubVals.get(0).U_ID_i.duplicate();
            // Prepare arrayList for return statement.
            ArrayList<designatedUserParamSCF> designatedUserPubParams = new ArrayList<>();
            designatedUserPubParams.add(userSpecificParams);
            printDesigUserParams(designatedUserPubParams);
            return designatedUserPubParams;
        } else {
            System.out.println("User check by KGC failed.");
            designatedUserParamSCF userSpecificParams = new designatedUserParamSCF();
            ArrayList<designatedUserParamSCF> designatedUserPubParams = new ArrayList<>();
            designatedUserPubParams.add(userSpecificParams);
            return designatedUserPubParams;
        }
    }

    public Element[] setPrivateKey(ArrayList<designatedUserParamSCF> desigUserParam, String userID, int T_M, int T_D) throws NoSuchAlgorithmException{
        // Logic => D_i = R_ID_i + {u_i.s}.X-Y_ID_i
        Element R_ID_i = X.mulZn(u_i);
        // Prepare to check s value.
        Element sComputed = cryptoParam.Zr.newElement();
        String prepHash_3 = userID + T_M + R_ID_i;
        hashFunc(sComputed, prepHash_3);
        if (sComputed.isEqual(desigUserParam.get(0).s)){
            System.out.println("Data ownership check passed.");
            // Retrieve partial private key.
            Element D_i = (R_ID_i.add(X.mulZn(u_i.mulZn(desigUserParam.get(0).s)))).sub(desigUserParam.get(0).Y_ID_i);
            // Compute Ephe. Secretkey.
            Element EphemSk = cryptoParam.G1.newRandomElement().setToZero();
            Element[] returnedVals = { u_i, D_i, EphemSk};
            //Check key correctness.
            Element Q_ID_i = cryptoParam.G1.newRandomElement();
            String prepHash_1 = userID + T_M;
            hashFunc(Q_ID_i, prepHash_1);
            Element outLeft = cryptoParam.pairing.pairing(D_i, cryptoParam.G.duplicate());
            Element outRight = cryptoParam.pairing.pairing(Q_ID_i, X.duplicate());
            if (outLeft.isEqual(outRight)){
                System.out.println("Key correctness check passed.");
                // Computing Ephem. Secret key.
                Element t_p = cryptoParam.Zr.newElement();
                String prepTpHash = Integer.toString(T_D);
                hashFunc(t_p, prepTpHash);
                returnedVals[2] = D_i.mulZn((u_i.add(t_p)).invert()); // Update EphemSk.
                return returnedVals;
            } else {
                System.out.println("Key correctness check failed.");
                returnedVals[0].setToZero();
                returnedVals[1].setToZero();
                return returnedVals;
            }
        } else {
            System.out.println("Data ownership check failed. Execution aborted");
            Element[] returnedVals = { u_i};
            returnedVals[0].setToZero();
            return returnedVals;
        }
    }

    public ArrayList<userPubKey> setPubKey(String userID, ArrayList<designatedUserParamSCF> desigUserParam, int T_M) throws NoSuchAlgorithmException{
        userPubKey pubKey = new userPubKey();
        pubKey.Q_ID_i = cryptoParam.G1.newRandomElement();
        String prepHash_1 = userID + T_M;
        hashFunc(pubKey.Q_ID_i, prepHash_1);
        pubKey.Y_i = desigUserParam.get(0).U_ID_i;
        ArrayList<userPubKey> userPublicKey = new ArrayList<>();
        userPublicKey.add(pubKey);
        return userPublicKey;
    }

    public ArrayList<signatureVals> ringSign(String ev, String[] L, Element sk, Element u_s, String msg, int T_D, ArrayList<userPubKey> userPublicKey) throws NoSuchAlgorithmException{
        System.out.println("Generating ring signature on: "+ msg + " ...Please wait...");
        // Initialize sig. values.
        signatureVals sigma_val = new signatureVals();
        // Compute link tag.
        sigma_val.tag_s = cryptoParam.Zr.newElement();
        String prepTagHash = ev + T_D + u_s.duplicate() + sk.duplicate();
        hashFunc(sigma_val.tag_s, prepTagHash);
        // Compute A_s
        Element t_p = cryptoParam.Zr.newElement();
        String prepTpHash = Integer.toString(T_D);
        hashFunc(t_p, prepTpHash);
        Element r_s = cryptoParam.Zr.newRandomElement();
        sigma_val.A_s = userPublicKey.get(0).Q_ID_i.duplicate().mulZn(r_s.duplicate().mulZn((u_s.duplicate().add(t_p.duplicate())).invert()));
        // Compute h_As value.
        Element[] A_i = new Element[L.length-1];
        for (int i = 0; i < L.length-1; i++) { 
            A_i[i]=cryptoParam.G1.newRandomElement();
        }
        Element sumA_i = cryptoParam.G1.newRandomElement().setToZero();
        for (int i = 0; i < L.length-1; i++) { 
            sumA_i=sumA_i.add(A_i[i]);
        }
        sigma_val.h_As = cryptoParam.Zr.newElement();
        String preph_AsHash = msg + sumA_i;
        hashFunc(sigma_val.h_As, preph_AsHash);
        // Compute h_As_prime value.
        Element h_As_prime = cryptoParam.Zr.newElement();
        String preph_As_primeHash = msg + ev + L + T_D + sigma_val.tag_s + sigma_val.h_As;   
        hashFunc(h_As_prime, preph_As_primeHash);
        // Compute B_s
        sigma_val.B_s = sk.mulZn(r_s.mulZn((h_As_prime.invert())));
        // Prepare arrayList for return statement.
        ArrayList<signatureVals> sigma_s = new ArrayList<>();
        sigma_s.add(sigma_val);
        System.out.println("Ring signature successfully generated.");
        printRingSig(sigma_s);
        return sigma_s;
    }

    public boolean ringVerify (ArrayList<signatureVals> sigma_s, String[] L, String msg, String ev, int T_D) throws NoSuchAlgorithmException{
        System.out.println("Verifying ring signature. Please wait...");
        // Compute h_As_prime value.
        Element h_As_prime = cryptoParam.Zr.newElement();
        String preph_As_primeHash = msg + ev + L + T_D + sigma_s.get(0).tag_s + sigma_s.get(0).h_As;  
        hashFunc(h_As_prime, preph_As_primeHash);
        // Equation check.
        Element LHS = cryptoParam.pairing.pairing(sigma_s.get(0).B_s.duplicate(), cryptoParam.G.duplicate());
        Element RHScompute = sigma_s.get(0).A_s.duplicate().mulZn(h_As_prime.duplicate().invert()).getImmutable();
        Element RHS = cryptoParam.pairing.pairing(RHScompute.duplicate(), X.duplicate());
        if (LHS.isEqual(RHS)){
            return true;
        } else {
            return false;
        }
    }

    // ======================= Utility functions =======================
    public void printStatements() {
        System.out.println("============ Public Key Parameters ==============");
        System.out.println("Generator (g): " +cryptoParam.G);
        System.out.println("============== PKG Parameters ===============");
        System.out.println("PRIVATE KEY OF KGC xInv : "+xInv);
        System.out.println("PUBLIC KEY OF KGC X : "+X);
        System.out.println("=================================================\n");
    }

    public void printDesigUserParams(ArrayList<designatedUserParamSCF> dUparams) {
        System.out.println("============ Specific user Public Parameters ==============");
        // System.out.println("Y_i: "+ dUparams.get(0).U_ID_i);
        System.out.println("Y_ID_i: "+ dUparams.get(0).Y_ID_i);
        System.out.println("s: "+ dUparams.get(0).s);
        System.out.println("=================================================\n");
    }

    public void printUserPublicVals(ArrayList<userPublicValues> userPubVals) {
        System.out.println("============ Specific user Public Values ==============");
        System.out.println("Q_ID_i: "+ userPubVals.get(0).Q_ID_i);
        System.out.println("U_ID_i: "+ userPubVals.get(0).U_ID_i);
        System.out.println("V_ID_i: "+ userPubVals.get(0).V_ID_i);
        System.out.println("W_ID_i: "+ userPubVals.get(0).W_ID_i);
        System.out.println("=================================================\n");
    }

    public void printRingSig(ArrayList<signatureVals> sigmaVals) {
        System.out.println("============ Sigma_s Parameters ==============");
        System.out.println("A_s: "+ sigmaVals.get(0).A_s);
        System.out.println("B_s: "+ sigmaVals.get(0).B_s);
        System.out.println("tag_s: "+ sigmaVals.get(0).tag_s);
        System.out.println("h_As: "+ sigmaVals.get(0).h_As);
        System.out.println("=================================================\n");
    }

    // Hashing algorithms begin. Specific usage will depend on output required for each method.
    private static void hashFunc(Element h, String s) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }

}
