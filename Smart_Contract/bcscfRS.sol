// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// A Smart Contract for SCFRSscheme
// Contract begins. 
contract bscfRSscheme {
    // Structs to be used in the contract.
    // Crypto structs.
    struct G1Point {
        uint X;
        uint Y;
    }

    struct publicParams{
        address AddrOfKGC; // Blockchain address of the KGC.
        G1Point pubKeyX; // Public key of KGC.
    }

    struct systemUsers{
        address userAddr; // User blockchain ID.
        string ID; // User  ID.
        G1Point U_ID; // U_ID.
        G1Point V_ID; // V_ID.
        G1Point W_ID; // W_ID.
        G1Point Q_ID; // Q_ID.
    } 

    // Generator of G1
    G1Point generator = g1Gen();
    // The prime q in the base field F_q for G1
    uint q_Val = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
 
    address immutable AddrOfKGC; // Contract deployer = MoH.
    
    // Mappings.
    mapping (address => publicParams)  public params; // Mapping for public parameters
    mapping (address => systemUsers)  public user; // Mapping for public parameters
	
    // Events begin.
    event PublicParamsPublished(string paramsPubMsg);
    event ScDeployment(string scfSCDeployed);
    event userPublicParamPublished(string userPubParamPubMsg);
    event embedPartialPrivKeyPublished(uint sVal, G1Point yVal);
    
    // Constructor for the contract.
    constructor() {
        AddrOfKGC = msg.sender;
		emit ScDeployment("Smart Contract for Scheme deployed");
    }
    
    // Creating an access modifier for KGC who deploys the Smart Contract.
    modifier KGC {
     require(msg.sender == AddrOfKGC);
     _;
     }

    // Function to register an HF.
    function publishPublicParams(address kgcAddr, G1Point memory kgcPubkey) KGC public returns (bool){
        params[kgcAddr] = publicParams(kgcAddr, kgcPubkey);
        emit PublicParamsPublished("Public params published by KGC"); // Emit event when KGC publishes params. 
        return true;
    }

    // Function to allow users publish their params.
    function publishUserPublicParams(string memory id, G1Point memory uId, G1Point memory vId, G1Point memory wid) public returns (bool){
        G1Point memory qid = hashToG1(abi.encodePacked(msg.sender)); // Address to bytes conversion.
        user[msg.sender] = systemUsers(msg.sender, id, uId, vId, wid,qid);
        emit userPublicParamPublished("Public params published by User"); // Emit event when KGC publishes params. 
        return true;
    }

    // Function to allow KGC publish embedded partial private key data.
    function publishEmbedPartialPrivKey(uint256 s, G1Point memory yID) KGC public returns (bool){
        emit embedPartialPrivKeyPublished(s,yID); // Emit event when KGC publishes embdedded partial private key. 
        return true;
    
    }

    // Function to verify ring signature. e(B_s,G)=e(h_As_prime_invAs,X)
    function ringVerify(string[] memory userList, string memory message, G1Point memory sigA_s, G1Point memory sigB_s, uint256 sigTag_s, uint256 sigh_as, string memory ev, uint256 T_D) public returns (bool){
        uint256 sigh_asPrime = uint256(keccak256(abi.encode(message,ev, userList,T_D, sigTag_s, AddrOfKGC, sigh_as)));
        G1Point memory hprimeInvMulAs = mul(sigA_s,inverseMod(sigh_asPrime, q_Val));
        require(
            bn128_check_pairing([
                sigB_s.X, sigB_s.Y,
                generator.X,generator.Y,
                hprimeInvMulAs.X, hprimeInvMulAs.Y,
                params[AddrOfKGC].pubKeyX.X, params[AddrOfKGC].pubKeyX.Y
            ]),
            'ring signature verification failed (pairing check failed)'
        );
        return true;
    }

    // Utility functions.
    function hashToG1(bytes memory message) internal returns (G1Point memory) {
        uint256 h = uint256(keccak256(message));
        return mul(generator, h);
    }

    // Return the product of a point on G1 and a scalar, i.e.
    // p == p.mul(1) and p.add(p) == p.mul(2) for all points p.
    function mul(G1Point memory p, uint s) internal returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := call(sub(gas(), 2000), 7, 0, input, 0x80, r, 0x60)
        // Use "invalid" to make gas estimation work
            switch success case 0 {invalid()}
        }
        require(success);
    }

    // Return the generator of G1
    function g1Gen() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    // Pairing check
    // Each G1 element has 256 bits X and 256 bits Y. ie. uint256[2]
    function bn128_check_pairing(uint256[8] memory input)
    public returns (bool) {
        uint256[1] memory result;
        bool success;
        assembly {
            // 0x08     id of precompiled bn256Pairing contract     (checking the elliptic curve pairings)
            // 0        number of ether to transfer
            // 256       size of call parameters, i.e. 8*256 bits == 256 bytes
            // 32        size of result (one 32 byte boolean!)
            success := call(sub(gas(), 2000), 0x08, 0, input, 256, result, 32)
        }
        require(success, "elliptic curve pairing failed");
        return result[0] == 1;
    }

    // Inverse modulo.
    function inverseMod(uint u, uint m) internal pure
        returns (uint)
    {
        if (u == 0 || u == m || m == 0)
            return 0;
        if (u > m)
            u = u % m;

        int t1;
        int t2 = 1;
        uint r1 = m;
        uint r2 = u;
        uint q;

        while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int(q) * t2, r2, r1 - q * r2);
        }

        if (t1 < 0)
            return (m - uint(-t1));

        return uint(t1);
    }
}