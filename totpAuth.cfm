<!---
<cfscript>
epoch = CreateDateTime(1970, 1, 1, 0, 0, 0);
testDate = CreateDateTime(1970,1,1,0,0,59);
epochTime = dateDiff("s", epoch, testDate);
writeOutput(epochTime & "<br>");
timeStep = Int(epochTime/30);
timeStep = formatBaseN(timeStep, 16);
writeDump("timeStep:" & timeStep);
writeOutput("<br>");
sharedSecret = "12345678901234567890";
sharedSecret = toBinary(toBase64(sharedSecret));
writeDump(binaryDecode(sharedSecret, "hex"));
sharedSecret = formatBaseN(sharedSecret, 16);
writeDump(sharedSecret);
writeDump(timeStep);
//sharedSecret = new Base32().encode(sharedSecret);
	totpMessage = hmac(timeStep, sharedSecret, "hmacSha1");
	writeOutput(totpMessage);
	totpMessage_array = ArrayNew(1);
	for (i = 1; i < len(trim(totpMessage)); i += 2){
		arrayAppend(totpMessage_array, mid(totpMessage, i, 2));
	}
	writeDump(totpMessage_array);
	writeoutput("<br>");
	offset = InputBaseN(Mid(totpMessage_array[20], 2, 1), 16) + 1; 
	/*binary =BitOr(
				BitOr(
					BitOr(
						BitSHLN(BitAnd(totpMessage_array[offset], InputBaseN("7f", 16)), 24), 
						BitSHLN(BitAnd(totpMessage_array[offset + 1], InputBaseN("ff", 16)), 16)
					), BitSHLN( BitAnd(totpMessage_array[offset + 2], InputBaseN("ff", 16)) , 8)
				), BitAnd(totpMessage_array[offset + 3], InputBaseN("ff", 16))
			);
	writeDump(binary);*/
	outputString = "";
	for (i = 0; i < 4; i++){
		outputString = outputString & totpMessage_array[offset + i];
	}
	writeOutput(outputString);
	outputString = inputBaseN(outputString, 16);
	outputString = BitAnd(outputString, InputBaseN("7fffffff", 16));
	writeOutput("<br>");
	writeOutput(Mid(outputString, len(outputString) - 6, 6));

</cfscript>--->
<cfscript>
epoch = CreateDateTime(1970,1,1,0,0,0);
testDate = createDateTime(2005,03,18,1,58,29);
epochTime = dateDiff("s", epoch, testDate);
timeStep = Int(epochTime/30);
timeStep = FormatBaseN(timeStep, 16);
//sharedSecret = binaryEncode(toBinary(toBase64("12345678901234567890")), "hex"); //Correct
sharedSecret = toBinary(toBase64("12345678901234567890"));
writeDump(sharedSecret);
counter = binaryEncode(toBinary(toBase64(0)), "hex");
hotpMessage = hmac(sharedSecret, counter, "hmacSha1");
writeDump(hotpMessage);
keySpec = createObject("java", "javax.crypto.spec.SecretKeySpec").init("HmacSHA1");
mac = createObject("java", "javax.crypto.Mac").getInstance(keySpec.getAlgorithm());
mac.init(keySpec);
buffer = createObject("java", "java.nio.ByteBuffer").allocate(8);
buffer.putLong(javaCast("long",2));
hotpMessage = mac.doFinal(buffer.array());
writeDump(binaryEncode(hotpMessage, "hex"));
</cfscript>
