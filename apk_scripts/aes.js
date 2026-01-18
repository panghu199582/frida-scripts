Java.perform(function() {
// AES Encryption Monitoring
		try {
			// Monitor javax.crypto.Cipher
			var Cipher = Java.use("javax.crypto.Cipher");
			
			// Hook doFinal method
			Cipher.doFinal.overload('[B').implementation = function(input) {
				console.log("\n[+] AES doFinal called");
				console.log("[+] Input: " + bytesToHex(input));
				var result = this.doFinal(input);
				console.log("[+] Output: " + bytesToHex(result));
				return result;
			};

			// Hook doFinal with offset
			Cipher.doFinal.overload('[B', 'int', 'int').implementation = function(input, inputOffset, inputLen) {
				console.log("\n[+] AES doFinal with offset called");
				console.log("[+] Input: " + bytesToHex(input));
				console.log("[+] Offset: " + inputOffset);
				console.log("[+] Length: " + inputLen);
				var result = this.doFinal(input, inputOffset, inputLen);
				console.log("[+] Output: " + bytesToHex(result));
				return result;
			};

			// Hook init method to get encryption mode and key
			Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
				console.log("\n[+] AES init called");
				console.log("[+] Operation Mode: " + getCipherMode(opmode));
				console.log("[+] Key: " + bytesToHex(key.getEncoded()));
				this.init(opmode, key);
			};

			// Hook init with IV
			Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode, key, params) {
				console.log("\n[+] AES init with IV called");
				console.log("[+] Operation Mode: " + getCipherMode(opmode));
				console.log("[+] Key: " + bytesToHex(key.getEncoded()));
				
				// Try to get IV if it's an IvParameterSpec
				try {
					var iv = Java.cast(params, Java.use("javax.crypto.spec.IvParameterSpec"));
					console.log("[+] IV: " + bytesToHex(iv.getIV()));
				} catch(e) {
					console.log("[+] Parameters: " + params);
				}
				
				this.init(opmode, key, params);
			};

			// Helper function to convert bytes to hex string
			function bytesToHex(bytes) {
				if (!bytes) return "null";
				var hex = "";
				for (var i = 0; i < bytes.length; i++) {
					hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
				}
				return hex;
			}

			// Helper function to get cipher mode name
			function getCipherMode(mode) {
				var modes = {
					1: "ENCRYPT_MODE",
					2: "DECRYPT_MODE",
					3: "WRAP_MODE",
					4: "UNWRAP_MODE"
				};
				return modes[mode] || "UNKNOWN_MODE";
			}

			console.log("[+] AES encryption monitoring hooks installed");
		} catch(e) {
			console.log("[-] Failed to install AES hooks: " + e);
		}
	
});