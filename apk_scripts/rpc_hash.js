rpc.exports = {
    generateHash: function(ts, devId, imsi, ver) {
        return new Promise(function(resolve, reject) {
            Java.perform(function() {
                try {
                    // 1. The 3 Static Keys (We extracted these!)
                    var HEX1 = "99bfd9a1a5db9a30eb09d1777f0d273d58123c0fcb18251cdb599d5c218a6e00ebe0113b751364e02915be796918acf4124b896b834cf4fea7251c3d7ef4625bdb7fc42d01c0d17aa26868eac3fdf707aa8a4035fee84115763a6d277e51df74b5885843bd1b2c004c258c49e074914520f5e51db0932131c68465611443002bf907131477312c1de36fd3918be25a0f5a05bb02ad15578c53d657bf5330a3b0752bf1a2668c3a1c9ceb9ec878fa1b445db23679dbed6207a285d14b61e12774099913321f1cba12c09ce968363ed49ef58671da54680805c538068d51efa12f292978779309c3ed1cfe94a15744beba59fa8c7b86c17cd51c54a2e52ecd969a60089bd6b4dccc30dfc8b846633c9798f70d724e10ff227b76b53408b006408c8df923ad5ae1cf2179ea74097267fb4b1f5a3f493d32bcfb038a20905cdd2c455c7477e849d3a8607370df163c4fbfae17961cddc7ffbf843bbe9055ea3960ab2386ee066e694b530ae4604a4bbffb178cd65475df50f733bd2bdacb5d2f65cb";
                    var HEX2 = "a7658cc8f674eea2a9719237b8d0c6c928122c4e94714c140ff1943af1b4be372a47816ff4efd802c17a80c19cae1a7640d17dd7384fbf836e3779a981ad7fd79126f4b1ee2b71b08e3d2f45d1d0e02f83550ecac9d72ebc4e43a8070752961c221cd9c390c1aeaffc7e85fc9fdcf7157a41baab152dc06450eec19087ef428d9cc212a739e50e9b65a4783e1263b3d9f9a4eb7931b9892b5fd9767f936d2e0a0adec2e26ab17124f4832e83336a55a40647a6f0f87f0577b8bb9c5a4fd4667cbe49ba45e9c06b8f4ccfc8a5c4338632fb72d769767758b2bba02b42fd2782de0668ebec41506571ac018e5e3799380a383556405f8e20e90dc6c8e5b2b903196099138d9b443f8a0092e5b3a90be35bc4deb610fb3e1448868696ef22f8941c3cc79d1300f6fecd1738e2bd5e9a5db6f8ba554295878a1b5d637f9f9fd626a8deaf8bb5f21db25837dea8aee3ec09ebe42f8d1ab3a5bcc1ee898bad514bc018a5653aa66b13599191c557ce5c443949d7f44b19918f10c4b7dee1ea028dabfd";
                    var HEX3 = "f02fc1a8120c856e1b3e0986075c6b5e4595d5ba28470d39fdc0bb5ccff4c4c4004c6cf06b627bf069055eef2a7cb8ffca3aa88a1b14ffaeb363c6dc6736ac3cb3c44fc4b4f9c054b9d93d4bfc1493685c622fd7abe8609be5eb11113fa4e6b8bb777fe7488027174867fecaa0c73662240e2bbf4c7522703e24861a0dc471686ded30f1a23adcfcf4de1bd92a05528da2d40e9adce1dda7253e0a4bbd5d854eeeb88608202b6fc19ba101889b972df35bcb1e0fc3906cbc331035ee4f391bedc1999321509c02901ef74fc3616e4a4b61d253911af644ffebb801cad110496eb7ee6e65c0a126d980743f91b0ed3156c31da62a0820968f4cfaa4d38424f562aa0e0960978e79ed8758ac7b35d28af3c5c2c81dab2b596f4e6f665f435b86915d2a1a1011d3bc61657d9915fc4b0135aaed12873ce3b203665d848157046007eb4d3304e521ca0d38720fdc0105ead00409a0fd6aca24786a03df875e612e2deb673bd0bf2983bc8b9bd34fc007538c1406e3cf40f39b32082e18486cdff21f";
                    
                    // 2. Logic: Salted TS
                    var tsLong = parseInt(ts);
                    var saltedTs = ts + "tw4ll3tn30";

                    // 3. Find ExternalFun Instance
                    var ExternalFun = Java.use("module.libraries.coresec.ExternalFun");
                    var instance = null;

                    // Try to find existing instance in memory first
                    Java.choose("module.libraries.coresec.ExternalFun", {
                        onMatch: function(i) { instance = i; },
                        onComplete: function() {}
                    });

                    // If not found, create new
                    if (!instance) {
                        instance = ExternalFun.$new();
                    }

                    // 4. Call Native Function
                    // Signature: (long, String, String, String, String, String, String, String)
                    var result = instance.encryptHmacRaw(
                        tsLong, 
                        devId, 
                        imsi, 
                        saltedTs, 
                        HEX1, 
                        HEX2, 
                        HEX3, 
                        ver
                    );
                    
                    resolve(result);
                } catch(e) {
                    reject(e.toString());
                }
            });
        });
    }
};
