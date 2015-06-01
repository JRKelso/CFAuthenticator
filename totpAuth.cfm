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
timeStep = formatBaseN(timeStep, 16);
while (Len(timeStep) < 16){
	timeStep = "0" & timeStep;
}
writeDump(timeStep);
//writeOutput("timeStep from 2005-3-18 1:58:29, 30 second timestep:" & timeStep & "<br>");
//writeDump(formatBaseN(timeStep, 16));
timeByteArray = createObject("java", "java.math.BigInteger").init("10" & timeStep, 16).toByteArray();
/*timeByteArray = createObject("java", "java.nio.ByteBuffer").allocate(8);
timeByteArray.putLong(javaCast("long", timeStep));
timeByteArray = timeByteArray.array();*/
writeDump(timeByteArray);
//writeDump(timeByteArray);
//sharedSecret = binaryEncode(toBinary(toBase64("12345678901234567890")), "hex"); //Correct
//sharedSecret = toBinary(toBase64("12345678901234567890"));
//sharedSecret = new Base32().encode("12345678901234567890");
//binaryKey = charsetDecode("12345678901234567890", "utf-8");
sharedKey = "12345678901234567890";
sharedKey = charsetDecode(sharedKey, "utf-8");
sharedKey = binaryEncode(sharedKey, "hex");
keyBytes = javaCast("string", sharedKey).getBytes();
writeOutput("KeyBytes");
writeDump(keyBytes);
writeOutput("<br>");
/*bigEndianKey = ArrayNew(1);
counter = 1;
for (i = arrayLen(keyBytes); i > 0; i--){
	bigEndianKey[counter] = keyBytes[i];
	counter++;
}
*/
counter = 1;
bigEndianTime = ArrayNew(1);
for (i = arrayLen(timeByteArray); i > 0; i--){
	bigEndianTime[counter] = timeByteArray[i];
	counter++;
}
bigEndianTimeStep = javaCast("byte[]", bigEndianTime);
writeDump(bigEndianTimeStep);



keySpec = createObject("java", "javax.crypto.spec.SecretKeySpec").init(keyBytes, "HmacSHA1");
mac = createObject("java", "javax.crypto.Mac").getInstance(keySpec.getAlgorithm());
mac.init(keySpec);
//buffer = createObject("java", "java.nio.ByteBuffer").allocate(8);
//buffer.putInt(javaCast("int",bigEndianTimeStep));
hotpMessage = mac.doFinal(bigEndianTimeStep);
writeDump(hotpMessage);
hexArray = ArrayNew(1);
counter = 1;
for (i = 1; i < arraylen(hotpMessage); i++){
	hexArray[counter] = hotpMessage[i];
	counter++;
}
writeDump(hexArray);

offsetStart = inputBaseN(mid(hexArray[arrayLen(hexArray)], 2, 1), 16);
offsetHex = "";
for (i = 0; i < 4; i++){
	offsetHex = offsetHex & hexArray[offsetStart + i];
}
writeDump(BitAnd(inputBaseN(offsetHex, 16), inputBaseN("7fffffff", 16)));
</cfscript>
