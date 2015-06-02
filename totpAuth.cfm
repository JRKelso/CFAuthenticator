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
testDate = createDateTime(2005,03,18,1,58,31);
epochTime = dateDiff("s", epoch, now());
timeStep = Int(epochTime/30);
while (Len(timeStep) < 16){
	timeStep = "0" & timeStep;
}
longObj = createObject("java", "java.lang.Long");
steps = longObj.toHexString(javaCast("long", timeStep)).ToUpperCase();
sharedKey = "12345678901234567890";
sharedKey = charsetDecode(sharedKey, "utf-8");
sharedKey = binaryEncode(sharedKey, "hex");
keyBytes = createObjecT("java", "java.math.BigInteger").init("10" & sharedKey, 16).ToByteArray();
for (i = 1; i < arrayLen(keyBytes); i++){
	keyBA[i] = keyBytes[i+1];
}
while (len(steps) < 16){
	steps = "0" & steps;
}
timeByteArray = createObject("java", "java.math.BigInteger").init("10" & steps, 16).toByteArray();
for (i = 1; i < ArrayLen(timeByteArray); i++){
	timeBA[i] = timeByteArray[i+1];
}
keySpec = createObject("java", "javax.crypto.spec.SecretKeySpec").init(keyBA, "HmacSHA1");
mac = createObject("java", "javax.crypto.Mac").getInstance(keySpec.getAlgorithm());
mac.init(keySpec);
hotpMessage = mac.doFinal(timeBA);
if (hotpMessage[arrayLen(hotpMessage)] < 0){
	offsetStart = bitAnd(hotpMessage[arrayLen(hotpMessage)], 255);
}
else {
	offsetStart = hotpMessage[arrayLen(hotpMessage)];
}
for (i = 1; i <= arrayLen(hotpMessage); i++){
	writeDump(i & ":" & hotpMessage[i]);
	writeOutput("<br>");
}
offset = inputBaseN(mid(formatBaseN(offsetStart, 16), 2, 1), 16) + 1;
otpTest = hotpMessage[offset] & hotpMessage[offset + 1] & hotpMessage[offset + 2] & hotpMessage[offset + 3];
firstTest = bitSHLN(bitAnd(hotpMessage[offset], inputBaseN("7f", 16)), 24);
secondTest = bitSHLN(bitAnd(hotpMessage[offset + 1], 255), 16);
thirdTest = bitSHLN(bitAnd(hotpMessage[offset + 2], 255), 8);
fourthTest = bitAnd(hotpMessage[offset + 3], 255);
writeDump("firstTest:" & firstTest);
writeDump("secondTest:" & secondTest);
writeDump("thirdTest:" & thirdTest);
writeDump("fourthTest:" & fourthTest);
writeDump(bitOr(bitOr(firstTest, secondTest), bitOr(thirdTest, fourthTest)));
writedump(otpTest);
binary = bitAnd(hotpMessage[offset], inputBaseN("7f",16)) & bitAnd(hotpMessage[offset + 1], inputBaseN("ff", 16)) & bitAnd(hotpMessage[offset + 2], inputBaseN("ff", 16)) & bitAnd(hotpMessage[offset + 3], inputBaseN("ff", 16));
writeDump(binary);
//writeDump(BitAnd(inputBaseN(offsetHex, 16), inputBaseN("7fffffff", 16)));
</cfscript>
